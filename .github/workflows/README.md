# GitHub Actions Workflows

## Release Binaries Workflow

The `release.yml` workflow automatically builds cross-platform binaries for the libp2p-chat application.

### Supported Platforms

- **Windows x64** (`x86_64-pc-windows-msvc`)
- **Linux x64** (`x86_64-unknown-linux-gnu`)
- **Linux ARM64** (`aarch64-unknown-linux-gnu`)
- **macOS ARM64** (`aarch64-apple-darwin`)

### Triggers

The workflow runs on:

1. **Tag pushes**: When you create and push a tag starting with `v` (e.g., `v1.0.0`)
2. **Pull requests**: On PRs to `main` or `master` branch
3. **Manual dispatch**: Can be triggered manually from the GitHub Actions tab

### Usage

#### Creating a Release

1. Create and push a tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. The workflow will automatically:
   - Build binaries for all platforms
   - Package them as archives (`.tar.gz` for Unix, `.zip` for Windows)
   - Create a GitHub release with all binaries attached

#### Manual Testing

You can also trigger the workflow manually:
1. Go to the "Actions" tab in your GitHub repository
2. Select "Release Binaries" workflow
3. Click "Run workflow"

### Artifacts

For each successful build, the following artifacts are created:

- `libp2p-chat-windows-x64.zip` - Windows executable
- `libp2p-chat-linux-x64.tar.gz` - Linux x64 binary
- `libp2p-chat-linux-arm64.tar.gz` - Linux ARM64 binary  
- `libp2p-chat-macos-arm64.tar.gz` - macOS ARM64 binary

### Cross-compilation Notes

- **Linux ARM64**: Uses `gcc-aarch64-linux-gnu` for cross-compilation
- **macOS ARM64**: Built on macOS runners for native compilation
- **Windows**: Built on Windows runners for native compilation

All builds use caching to speed up compilation times. 