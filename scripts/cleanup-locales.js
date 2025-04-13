const fs = require('fs');
const path = require('path');

exports.default = async function(context) {
  const localesDir = path.join(context.appOutDir, 'locales');
  const keep = new Set(['en-US.pak', 'tr.pak']);

  // Clean up the locales directory
  if (fs.existsSync(localesDir)) {
    const files = fs.readdirSync(localesDir);
    for (const file of files) {
      if (!keep.has(file)) {
        fs.unlinkSync(path.join(localesDir, file));
      }
    }
  }

  // Files to remove from the output directory
  const extraJunk = [
    'LICENSES.chromium.html',
    'd3dcompiler_47.dll',
    'libGLESv2.dll'
  ];

  for (const file of extraJunk) {
    const targetPath = path.join(context.appOutDir, file);
    if (fs.existsSync(targetPath)) {
      fs.unlinkSync(targetPath);
    }
  }
};
