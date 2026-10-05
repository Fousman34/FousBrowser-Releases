// Run after committing a new signed engine manifest. No credentials required.
import fs from 'node:fs';
import path from 'node:path';
const root = path.resolve(import.meta.dirname, '../browsers/antidetect');
const releases = fs.readdirSync(root, { withFileTypes: true })
  .filter(entry => entry.isDirectory() && fs.existsSync(path.join(root, entry.name, 'release.json')))
  .map(entry => {
    const dir = path.join(root, entry.name);
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'release.json'), 'utf8'));
    for (const file of ['SHA256SUMS', 'SHA256SUMS.asc']) {
      if (!fs.existsSync(path.join(dir, file))) throw new Error(`Missing ${dir}/${file}`);
    }
    const tag = `antidetect-v${manifest.version}`;
    const base = 'https://github.com/Fousman34/FousBrowser-Releases/releases/';
    return {
      tag_name: tag, draft: false, prerelease: false, body: manifest.notes,
      html_url: `${base}tag/${tag}`,
      assets: [manifest.asset_name, 'SHA256SUMS', 'SHA256SUMS.asc'].map(name => ({
        name, browser_download_url: `${base}download/${tag}/${name}`
      }))
    };
  });
fs.writeFileSync(path.join(root, 'releases.json'), `${JSON.stringify(releases, null, 2)}\n`);
