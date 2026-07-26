#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOCRYPTFS_BIN="${SCRIPT_DIR}/gocryptfs"
EXTERNAL_PROVIDER="https://192.168.2.223:9443"
KEY_NAME="test-vault"
TEST_PASS="testpassword123"

if [[ ! -x "$GOCRYPTFS_BIN" ]]; then
    echo "gocryptfs binary not found or not executable at ${GOCRYPTFS_BIN}. Building now..."
    export PATH="${HOME}/.local/go/bin:${PATH}"
    (cd "${SCRIPT_DIR}" && ./build.bash)
fi

TMP_DIR="$(mktemp -d /tmp/gocryptfs_ext_test.XXXXXX)"
CIPHER_DIR="${TMP_DIR}/cipher"
MOUNT_DIR="${TMP_DIR}/mount"

cleanup() {
    echo "--> Cleaning up..."
    if mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
        fusermount -u "${MOUNT_DIR}" || true
    fi
    rm -rf "${TMP_DIR}"
    echo "--> Cleanup complete."
}
trap cleanup EXIT

mkdir -p "${CIPHER_DIR}" "${MOUNT_DIR}"

echo "========================================================"
echo " Starting External Encryption Provider Integration Test"
echo " Target Provider: ${EXTERNAL_PROVIDER}"
echo " Temporary Workspace: ${TMP_DIR}"
echo "========================================================"

echo ""
echo "Step 1: Initializing encrypted storage directory..."
"${GOCRYPTFS_BIN}" -init -extpass "echo ${TEST_PASS}" "${CIPHER_DIR}"

echo ""
echo "Step 2: Mounting filesystem with external provider integration..."
"${GOCRYPTFS_BIN}" -extpass "echo ${TEST_PASS}" \
    -external-provider "${EXTERNAL_PROVIDER}" \
    -key-name "${KEY_NAME}" \
    "${CIPHER_DIR}" "${MOUNT_DIR}"

echo ""
echo "Step 3: Writing test files to mounted filesystem..."
TEST_FILE="${MOUNT_DIR}/sample.txt"
TEST_CONTENT="Hello world! External provider encryption test at $(date)"
echo "${TEST_CONTENT}" > "${TEST_FILE}"

echo "--> Created test file: ${TEST_FILE}"
ORIGINAL_HASH=$(sha256sum "${TEST_FILE}" | cut -d' ' -f1)
echo "--> File SHA256 (Mounted): ${ORIGINAL_HASH}"

echo ""
echo "Step 4: Unmounting filesystem..."
fusermount -u "${MOUNT_DIR}"
sleep 1

if [[ -f "${TEST_FILE}" ]]; then
    echo "ERROR: Test file still visible after unmounting!"
    exit 1
fi
echo "--> Verified filesystem unmounted cleanly."

echo ""
echo "Step 5: Remounting filesystem with external provider..."
"${GOCRYPTFS_BIN}" -extpass "echo ${TEST_PASS}" \
    -external-provider "${EXTERNAL_PROVIDER}" \
    -key-name "${KEY_NAME}" \
    "${CIPHER_DIR}" "${MOUNT_DIR}"

echo ""
echo "Step 6: Reading back test file and verifying integrity..."
READ_CONTENT=$(cat "${TEST_FILE}")
READ_HASH=$(sha256sum "${TEST_FILE}" | cut -d' ' -f1)

echo "--> Read content: ${READ_CONTENT}"
echo "--> Read SHA256:  ${READ_HASH}"

if [[ "${READ_HASH}" != "${ORIGINAL_HASH}" ]]; then
    echo "ERROR: Hash mismatch! Original=${ORIGINAL_HASH}, Read=${READ_HASH}"
    exit 1
fi

echo ""
echo "========================================================"
echo " SUCCESS: External encryption provider test passed!"
echo "========================================================"
