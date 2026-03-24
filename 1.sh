#!/bin/bash
# save_as: apply_license.sh

YEAR="2026"
HOLDER="Uk1d"

# C 文件头（/* */ 风格）
C_HEADER="/* Copyright $YEAR $HOLDER
 *
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

"

# Go 文件头（// 风格）
GO_HEADER="// Copyright $YEAR $HOLDER
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

"

echo "[*] Processing C/C++ files (*.c, *.h)..."
find . -type f \( -name "*.c" -o -name "*.h" \) \
  ! -path "./.git/*" ! -path "./vendor/*" ! -path "./libbpf/*" | while read f; do
    if ! grep -q "Copyright.*$HOLDER" "$f"; then
        echo "$C_HEADER" | cat - "$f" > temp && mv temp "$f"
        echo "  [+] $f"
    fi
done

echo "[*] Processing Go files (*.go)..."
find . -type f -name "*.go" \
  ! -path "./.git/*" ! -path "./vendor/*" | while read f; do
    if ! grep -q "Copyright.*$HOLDER" "$f"; then
        echo "$GO_HEADER" | cat - "$f" > temp && mv temp "$f"
        echo "  [+] $f"
    fi
done

echo "[*] Done. Run 'git diff' to review changes."