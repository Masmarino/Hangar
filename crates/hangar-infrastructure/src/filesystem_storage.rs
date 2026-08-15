use async_trait::async_trait;
use futures_util::TryStreamExt;
use hangar_domain::storage::{ByteStream, StorageBackendPort, StorageError, VolumeSpace};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

pub struct FilesystemStorageBackend {
    root: PathBuf,
}

impl FilesystemStorageBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn repository_root(&self, repository_id: Uuid) -> PathBuf {
        self.root.join(repository_id.to_string())
    }

    /// Rejects `.`/`..`/absolute segments so `Path::join` can't escape the
    /// repository root — validated, not canonicalized, since a write target
    /// doesn't exist yet.
    fn object_path(&self, repository_id: Uuid, path: &str) -> Result<PathBuf, StorageError> {
        if path.is_empty() {
            return Err(StorageError::Io("object path must not be empty".to_string()));
        }
        if path.starts_with('/') || path.starts_with('\\') {
            return Err(StorageError::Io(format!("object path must be relative, got {path:?}")));
        }
        if path.contains('\\') || path.contains('\0') {
            return Err(StorageError::Io(format!("object path contains an illegal character: {path:?}")));
        }
        for segment in path.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(StorageError::Io(format!("object path contains an illegal segment {segment:?}: {path:?}")));
            }
        }
        Ok(self.repository_root(repository_id).join(path))
    }
}

#[async_trait]
impl StorageBackendPort for FilesystemStorageBackend {
    async fn write(&self, repository_id: Uuid, path: &str, data: &[u8]) -> Result<(), StorageError> {
        let target = self.object_path(repository_id, path)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).await.map_err(|e| StorageError::Io(e.to_string()))?;
        }
        // Append a per-write UUID to the full name (not with_extension, which
        // would collide "pkg.tgz"/"pkg.sig" on the same "pkg.tmp" staging file).
        let file_name = target.file_name().ok_or_else(|| StorageError::Io(format!("object path has no file name: {path:?}")))?;
        let tmp_path = target.with_file_name(format!("{}.tmp-{}", file_name.to_string_lossy(), Uuid::new_v4()));
        fs::write(&tmp_path, data).await.map_err(|e| StorageError::Io(e.to_string()))?;
        fs::rename(&tmp_path, &target).await.map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    async fn read(&self, repository_id: Uuid, path: &str) -> Result<Vec<u8>, StorageError> {
        let target = self.object_path(repository_id, path)?;
        fs::read(&target).await.map_err(|e| StorageError::NotFound(e.to_string()))
    }

    async fn read_stream(&self, repository_id: Uuid, path: &str) -> Result<ByteStream, StorageError> {
        let target = self.object_path(repository_id, path)?;
        let file = fs::File::open(&target).await.map_err(|e| StorageError::NotFound(e.to_string()))?;
        Ok(Box::pin(ReaderStream::new(file).map_err(|e| StorageError::Io(e.to_string()))))
    }

    async fn delete(&self, repository_id: Uuid, path: &str) -> Result<(), StorageError> {
        let target = self.object_path(repository_id, path)?;
        match fs::remove_file(&target).await {
            Ok(()) => Ok(()),
            // Deleting something that's already gone is a no-op, not a failure — this also
            // makes concurrent deletes of the same object race-free (both callers succeed).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }

    async fn used_bytes(&self, repository_id: Uuid) -> Result<u64, StorageError> {
        let root = self.repository_root(repository_id);
        Ok(directory_size(&root).await.unwrap_or(0))
    }

    async fn is_healthy(&self) -> bool {
        fs::create_dir_all(&self.root).await.is_ok() && fs::metadata(&self.root).await.is_ok()
    }

    async fn volume_space(&self) -> Result<VolumeSpace, StorageError> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            // statvfs fails on a path that doesn't exist yet.
            std::fs::create_dir_all(&root).map_err(|e| StorageError::Io(e.to_string()))?;
            statvfs(&root)
        })
        .await
        .map_err(|e| StorageError::Io(e.to_string()))?
    }
}

#[cfg(unix)]
fn statvfs(path: &Path) -> Result<VolumeSpace, StorageError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| StorageError::Io(e.to_string()))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a valid, NUL-terminated C string for the lifetime of
    // this call, and `stat` is a plain-old-data struct libc fully populates.
    let result = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if result != 0 {
        return Err(StorageError::Io(std::io::Error::last_os_error().to_string()));
    }
    let block_size = stat.f_frsize as u64;
    Ok(VolumeSpace { total_bytes: stat.f_blocks as u64 * block_size, free_bytes: stat.f_bavail as u64 * block_size })
}

fn directory_size(dir: &Path) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, std::io::Error>> + Send + '_>> {
    Box::pin(async move {
        let mut total = 0u64;
        let mut entries = match fs::read_dir(dir).await {
            Ok(entries) => entries,
            Err(_) => return Ok(0),
        };
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_dir() {
                total += directory_size(&entry.path()).await?;
            } else {
                total += metadata.len();
            }
        }
        Ok(total)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_then_reads_back_the_same_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());
        let repository_id = Uuid::new_v4();
        backend.write(repository_id, "package/1.0.0.tgz", b"hello").await.unwrap();
        let data = backend.read(repository_id, "package/1.0.0.tgz").await.unwrap();
        assert_eq!(data, b"hello");
    }

    #[tokio::test]
    async fn read_stream_yields_the_same_bytes_as_read() {
        use futures_util::StreamExt;

        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());
        let repository_id = Uuid::new_v4();
        backend.write(repository_id, "package/1.0.0.tgz", b"streamed-hello").await.unwrap();

        let mut stream = backend.read_stream(repository_id, "package/1.0.0.tgz").await.unwrap();
        let mut collected = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, b"streamed-hello");
    }

    #[tokio::test]
    async fn read_stream_of_a_missing_object_fails_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());
        assert!(backend.read_stream(Uuid::new_v4(), "never-written.tgz").await.is_err());
    }

    #[tokio::test]
    async fn deleting_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());
        let repository_id = Uuid::new_v4();
        backend.write(repository_id, "file.bin", b"data").await.unwrap();
        backend.delete(repository_id, "file.bin").await.unwrap();
        assert!(backend.read(repository_id, "file.bin").await.is_err());
    }

    #[tokio::test]
    async fn deleting_an_already_deleted_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());
        let repository_id = Uuid::new_v4();
        backend.write(repository_id, "file.bin", b"data").await.unwrap();
        backend.delete(repository_id, "file.bin").await.unwrap();
        backend.delete(repository_id, "file.bin").await.unwrap();
    }

    #[tokio::test]
    async fn used_bytes_sums_all_files_in_the_repository() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());
        let repository_id = Uuid::new_v4();
        backend.write(repository_id, "a.bin", b"12345").await.unwrap();
        backend.write(repository_id, "nested/b.bin", b"1234567890").await.unwrap();
        assert_eq!(backend.used_bytes(repository_id).await.unwrap(), 15);
    }

    #[tokio::test]
    async fn rejects_a_path_that_escapes_the_repository_directory() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());
        let repository_id = Uuid::new_v4();

        for hostile in ["../escape.txt", "../../etc/passwd", "nested/../../escape.txt", "/etc/passwd", "", "a//b", "./a", "a/", "a\\b"] {
            let write = backend.write(repository_id, hostile, b"pwned").await;
            assert!(write.is_err(), "write should reject {hostile:?}");
            assert!(backend.read(repository_id, hostile).await.is_err(), "read should reject {hostile:?}");
            assert!(backend.delete(repository_id, hostile).await.is_err(), "delete should reject {hostile:?}");
        }

        assert!(!dir.path().join("escape.txt").exists());
        assert!(!dir.path().parent().unwrap().join("escape.txt").exists());
    }

    #[tokio::test]
    async fn two_paths_sharing_a_stem_keep_their_own_content() {
        let dir = tempfile::tempdir().unwrap();
        let backend = std::sync::Arc::new(FilesystemStorageBackend::new(dir.path()));
        let repository_id = Uuid::new_v4();

        let tarball = {
            let backend = backend.clone();
            tokio::spawn(async move { backend.write(repository_id, "pkg-1.0.0.tgz", b"tarball-bytes").await })
        };
        let signature = {
            let backend = backend.clone();
            tokio::spawn(async move { backend.write(repository_id, "pkg-1.0.0.sig", b"signature").await })
        };
        tarball.await.unwrap().unwrap();
        signature.await.unwrap().unwrap();

        assert_eq!(backend.read(repository_id, "pkg-1.0.0.tgz").await.unwrap(), b"tarball-bytes");
        assert_eq!(backend.read(repository_id, "pkg-1.0.0.sig").await.unwrap(), b"signature");
    }

    #[tokio::test]
    async fn no_staging_files_are_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());
        let repository_id = Uuid::new_v4();
        backend.write(repository_id, "pkg-1.0.0.tgz", b"tarball-bytes").await.unwrap();

        let mut entries = fs::read_dir(dir.path().join(repository_id.to_string())).await.unwrap();
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names, vec!["pkg-1.0.0.tgz".to_string()]);
    }

    #[tokio::test]
    async fn reports_healthy_when_the_root_is_writable() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());
        assert!(backend.is_healthy().await);
    }

    #[tokio::test]
    async fn reports_nonzero_total_and_free_volume_space() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FilesystemStorageBackend::new(dir.path());

        let space = backend.volume_space().await.unwrap();

        assert!(space.total_bytes > 0);
        assert!(space.free_bytes <= space.total_bytes);
    }

    #[tokio::test]
    async fn reports_volume_space_even_before_the_root_directory_exists() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("not-created-yet");
        let backend = FilesystemStorageBackend::new(&root);

        let space = backend.volume_space().await.unwrap();

        assert!(space.total_bytes > 0);
        assert!(root.exists());
    }
}
