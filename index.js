/**
 * @smilintux/sksecurity
 *
 * SKSecurity - AI-native security tools.
 * JS/TS bridge to the Python sksecurity package.
 * Install: pip install sksecurity
 */

const { execSync } = require("child_process");

const VERSION = "1.2.1";
const PYTHON_PACKAGE = "sksecurity";

function checkInstalled() {
  try {
    execSync(`python3 -c "import sksecurity"`, { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

function run(args) {
  return execSync(`sksecurity ${args}`, { encoding: "utf-8" });
}

module.exports = { VERSION, PYTHON_PACKAGE, checkInstalled, run };
