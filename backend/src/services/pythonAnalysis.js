const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PYTHON_API_URL =
  process.env.FORENSICS_API_URL || 'http://127.0.0.1:8000';

const SUPPORTED_EXTENSIONS = new Set([
  '.txt', '.log', '.eml', '.csv', '.json'
]);

async function analyzeFile(filePath, expectedSha256, originalFilename) {
  const filename = path.basename(originalFilename || filePath);
  const extension = path.extname(filename).toLowerCase();

  if (!SUPPORTED_EXTENSIONS.has(extension)) {
    return {
      status: 'unsupported',
      message: `Python analysis does not support ${extension || 'this file type'}`
    };
  }

  const data = fs.readFileSync(filePath);
  const actualSha256 = crypto
    .createHash('sha256')
    .update(data)
    .digest('hex');

  if (actualSha256 !== expectedSha256) {
    throw new Error('Evidence integrity check failed before analysis');
  }

  const form = new FormData();
  form.append(
    'file',
    new Blob([data], { type: 'application/octet-stream' }),
    filename
  );

  const response = await fetch(`${PYTHON_API_URL}/analyze`, {
    method: 'POST',
    body: form,
    signal: AbortSignal.timeout(30000)
  });

  if (!response.ok) {
    throw new Error(`Python analysis returned HTTP ${response.status}`);
  }

  const result = await response.json();

  if (result.sha256 !== actualSha256) {
    throw new Error('Python analysis hash does not match original evidence');
  }

  return {
    status: 'completed',
    ...result
  };
}

module.exports = { analyzeFile };
