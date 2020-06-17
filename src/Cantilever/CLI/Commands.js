import fs from "fs";
import path from "path";

export function readFileSyncUtf8(filePath) {
  return function() {
    return fs.readFileSync(filePath, "utf8");
  };
}

export function writeFileSyncUtf8(filePath) {
  return function(content) {
    return function() {
      const dir = path.dirname(filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(filePath, content, "utf8");
    };
  };
}

export function fileExistsSync(filePath) {
  return function() {
    return fs.existsSync(filePath);
  };
}

export function getHighResTimeMs() {
  const hr = process.hrtime();
  return hr[0] * 1000 + hr[1] / 1000000;
}
