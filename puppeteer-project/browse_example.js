const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ args: ['--no-sandbox'] });
  const page = await browser.newPage();

  try {
    await page.goto('https://www.example.com', { waitUntil: 'networkidle2' });
    const title = await page.title();
    console.log(`Page Title: ${title}`);
  } catch (error) {
    console.error(`Error during browsing: ${error.message}`);
  } finally {
    await browser.close();
  }
})();