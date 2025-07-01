const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.goto('https://www.google.com');
  await page.screenshot({ path: 'google.png' });

  await browser.close();
})();