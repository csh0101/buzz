#!/bin/bash
# Buzz 桌面版一键安装（macOS Apple Silicon）
# 用法：curl -fsSL https://dl.robogo-fat2.d-robotics.cc/install.sh | bash
set -euo pipefail
echo "⬇️  下载 Buzz 桌面版..."
curl -fSL --progress-bar -o /tmp/Buzz.zip https://dl.robogo-fat2.d-robotics.cc/Buzz-0.5.3-aarch64.zip
echo "📦 安装到 /Applications..."
rm -rf /tmp/buzz-install && mkdir -p /tmp/buzz-install
unzip -oq /tmp/Buzz.zip -d /tmp/buzz-install
rm -rf /Applications/Buzz.app 2>/dev/null || true
mv /tmp/buzz-install/Buzz.app /Applications/
xattr -dr com.apple.quarantine /Applications/Buzz.app 2>/dev/null || true
rm -rf /tmp/Buzz.zip /tmp/buzz-install
echo "✅ 安装完成，启动 Buzz..."
open /Applications/Buzz.app
