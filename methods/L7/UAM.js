const playwright = require('playwright-extra')
const iPhone = playwright.devices['iPhone 12'];
var colors = require('colors');

const url = process.argv[2];

if (process.argv.length !== 2) {
  console.log(`                       
      Usage: node UAM <host>
      Usage: node UAM https://example.com
      -------------------------------------------------------.0
      Made by xd                        
  `.rainbow);
  process.exit(0);
};


    console.log(`Starting Browser Engine!`);

    playwright.firefox.launch({headless: true}).then(async browser => {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(url)
      /*
      await page.waitForTimeout(5000)
      await page.screenshot({ path: 'ff.png', fullPage: true })
      */
      console.log("Request bypassed")
    });

process.on('uncaughtException', function (err) {
    console.log(err);
});
process.on('unhandledRejection', function (err) {
    console.log(err);
});