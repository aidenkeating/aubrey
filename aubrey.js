'use strict';

const exec = require('child-process-promise').exec;
const fs = require('fs');
const _ = require('lodash');

/**
 * Shells out to nsp to get vulnerabilities.
 * 
 * @returns {Promise} A promise for the execution of nsp check.
 */
function listVulnerabilities() {
  return exec('nsp check --output json');
}

/**
 * Parses the JSON block returned by nsp and gets the advisories for each.
 * 
 * @param {Object} vulnerabilities - An nsp response block.
 * @return {Array} A list of advisories.
 */
function parseVulnerabilities(vulnerabilities) {
  return _(vulnerabilities).map('advisory').uniq().value();
}

/**
 * Creates and writes the .nsprc file to the current directory.
 * 
 * @param {Array} vulnerabilities - A list of vulnerability advisories.
 */
function writeVulnerabilityReport(vulnerabilities) {
  const fileContents = JSON.stringify({exceptions: vulnerabilities}, null, 2);

  fs.writeFile('.nsprc', fileContents, function reportWriteComplete(err) {
    if(err) {
      console.error('Something went wrong while writing file.');
      process.exit(1);
    }
    console.log('Done, you\'re welcome');
    process.exit(0);
  });
}

listVulnerabilities()
  .then(() => process.exit(0))
  .catch(function(result) {
    if(result.stderr) {
      const parsedResult = JSON.parse(result.stderr);
      const parsedVulnerabilities = parseVulnerabilities(parsedResult);

      return writeVulnerabilityReport(parsedVulnerabilities);
    }
  });
