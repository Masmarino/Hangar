// Matches from the right — an image name's own segments can legally be "blobs", "manifests", etc., so the real operation suffix is always the rightmost match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerOperation {
    BlobUploadStart { image_name: String },
    BlobUploadChunk { image_name: String, upload_id: String },
    Blob { image_name: String, digest: String },
    Manifest { image_name: String, reference: String },
    TagsList { image_name: String },
}

impl DockerOperation {
    pub fn image_name(&self) -> &str {
        match self {
            DockerOperation::BlobUploadStart { image_name }
            | DockerOperation::BlobUploadChunk { image_name, .. }
            | DockerOperation::Blob { image_name, .. }
            | DockerOperation::Manifest { image_name, .. }
            | DockerOperation::TagsList { image_name } => image_name,
        }
    }
}

pub fn parse_operation(rest: &str) -> Option<DockerOperation> {
    if let Some(image_name) = rest.strip_suffix("/tags/list") {
        return Some(DockerOperation::TagsList { image_name: image_name.to_string() });
    }
    if let Some((image_name, after)) = rest.rsplit_once("/blobs/uploads/") {
        return Some(if after.is_empty() {
            DockerOperation::BlobUploadStart { image_name: image_name.to_string() }
        } else {
            DockerOperation::BlobUploadChunk { image_name: image_name.to_string(), upload_id: after.to_string() }
        });
    }
    if let Some((image_name, digest)) = rest.rsplit_once("/blobs/") {
        return Some(DockerOperation::Blob { image_name: image_name.to_string(), digest: digest.to_string() });
    }
    if let Some((image_name, reference)) = rest.rsplit_once("/manifests/") {
        return Some(DockerOperation::Manifest { image_name: image_name.to_string(), reference: reference.to_string() });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_blob_upload_start_path() {
        assert_eq!(parse_operation("myimage/blobs/uploads/"), Some(DockerOperation::BlobUploadStart { image_name: "myimage".to_string() }));
    }

    #[test]
    fn parses_a_blob_upload_chunk_path() {
        assert_eq!(
            parse_operation("myimage/blobs/uploads/abc-123"),
            Some(DockerOperation::BlobUploadChunk { image_name: "myimage".to_string(), upload_id: "abc-123".to_string() })
        );
    }

    #[test]
    fn parses_a_blob_download_path() {
        assert_eq!(
            parse_operation("myimage/blobs/sha256:deadbeef"),
            Some(DockerOperation::Blob { image_name: "myimage".to_string(), digest: "sha256:deadbeef".to_string() })
        );
    }

    #[test]
    fn a_nested_image_name_that_itself_contains_blobs_still_resolves_from_the_right() {
        assert_eq!(
            parse_operation("library/blobs/utility/blobs/sha256:deadbeef"),
            Some(DockerOperation::Blob { image_name: "library/blobs/utility".to_string(), digest: "sha256:deadbeef".to_string() })
        );
    }

    #[test]
    fn returns_none_for_an_unrecognized_shape() {
        assert_eq!(parse_operation("myimage/nonsense"), None);
    }

    #[test]
    fn parses_a_manifest_path_with_a_tag_reference() {
        assert_eq!(
            parse_operation("myimage/manifests/latest"),
            Some(DockerOperation::Manifest { image_name: "myimage".to_string(), reference: "latest".to_string() })
        );
    }

    #[test]
    fn parses_a_manifest_path_with_a_digest_reference() {
        assert_eq!(
            parse_operation("myimage/manifests/sha256:deadbeef"),
            Some(DockerOperation::Manifest { image_name: "myimage".to_string(), reference: "sha256:deadbeef".to_string() })
        );
    }

    #[test]
    fn parses_a_tags_list_path() {
        assert_eq!(parse_operation("myimage/tags/list"), Some(DockerOperation::TagsList { image_name: "myimage".to_string() }));
    }
}
