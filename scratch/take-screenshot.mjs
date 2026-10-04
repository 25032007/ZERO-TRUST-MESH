import puppeteer from 'puppeteer';
import { mkdirSync } from 'fs';

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  mkdirSync('../docs/screenshots', { recursive: true });

  await page.setViewport({ width: 1280, height: 800 });
  await page.goto('http://localhost:4000', { waitUntil: 'networkidle2' });
  
  // Try to click runAll to generate some data
  try {
    await page.click('#runAll');
    await new Promise(r => setTimeout(r, 2000));
  } catch (e) {}

  await page.screenshot({ path: '../docs/screenshots/desktop.png', fullPage: true });

  await page.setViewport({ width: 390, height: 844 });
  await new Promise(r => setTimeout(r, 500));
  await page.screenshot({ path: '../docs/screenshots/mobile.png', fullPage: true });

  await browser.close();
})();
