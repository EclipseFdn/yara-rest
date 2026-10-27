## Yara Rest Service Change Log

### [Unreleased]

Stream uploads to disk instead of buffering them in memory; uploads over `MAX_UPLOAD_SIZE_MB` now get a 413 response

### [v0.1.1] (12/05/2026)

Send proper error responses in case a scan failed instead of an internal server error

### [v0.1.0] (Feb. 2026)

Initial release.