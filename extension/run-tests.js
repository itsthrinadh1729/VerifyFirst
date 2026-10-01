const puppeteer = require('puppeteer');
const path = require('path');

async function runTests() {
  const extensionPath = path.resolve(__dirname);
  console.log('Loading extension from:', extensionPath);

  const browser = await puppeteer.launch({
    headless: "new",
    channel: "chrome",
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  });

  try {
    const page = await browser.newPage();
    
    // Listen for extension logs
    page.on('console', msg => {
      if (msg.text().includes('[VerifyFirst]')) {
        console.log('EXT:', msg.text());
      }
    });

    console.log('Navigating to test page...');
    // We navigate to a mock WhatsApp page to load the content scripts
    await page.goto('https://example.com');
    
    // Inject fake WhatsApp DOM safely
    await page.evaluate(() => {
      if (!document.getElementById('app')) {
        const app = document.createElement('div');
        app.id = 'app';
        app.innerHTML = `
          <div id="main" style="padding: 20px;">
             <div data-testid="conversation-panel-messages"></div>
          </div>
        `;
        document.body.appendChild(app);
      }
    });

    // Wait a bit for the extension to initialize
    await new Promise(r => setTimeout(r, 2000));

    // The injectMockMessage helper
    const injectMockMessage = async (content, isFile = false) => {
      await page.evaluate((content, isFile) => {
        const panel = document.querySelector('[data-testid="conversation-panel-messages"]') || document.body;
        const msg = document.createElement('div');
        
        if (isFile) {
          msg.innerHTML = '<div data-testid="msg-document"><div data-testid="document-title">' + content + '</div></div>';
        } else {
          msg.innerHTML = '<div><a href="' + content + '" target="_blank" rel="noopener noreferrer">' + content + '</a></div>';
        }
        
        panel.appendChild(msg);
        console.log("Injected mock message:", content);
      }, content, isFile);
      // Wait for extension processing
      await new Promise(r => setTimeout(r, 3000));
    };

    console.log('--- A. File discovery ---');
    console.log('Injecting backup.zip (SAFE)');
    await injectMockMessage("backup.zip", true);
    let overlayHtml = await page.evaluate(() => document.getElementById('verifyfirst-overlay-container')?.shadowRoot?.innerHTML || '');
    console.log('Overlay present for backup.zip?', overlayHtml.includes('overlay-card'));

    console.log('Injecting invoice.pdf.exe (DANGEROUS)');
    await injectMockMessage("invoice.pdf.exe", true);
    overlayHtml = await page.evaluate(() => document.getElementById('verifyfirst-overlay-container')?.shadowRoot?.innerHTML || '');
    console.log('Overlay present for invoice.pdf.exe?', overlayHtml.includes('Dangerous file detected'));
    
    // B1. Details
    console.log('--- B1. Details flow ---');
    // Find the details button in the shadow root and click it
    await page.evaluate(() => {
      const shadow = document.getElementById('verifyfirst-overlay-container').shadowRoot;
      const detailsBtn = Array.from(shadow.querySelectorAll('button')).find(b => b.textContent === 'Details');
      if (detailsBtn) detailsBtn.click();
    });
    console.log('Clicked Details button');
    await new Promise(r => setTimeout(r, 2000));

    // To check Security Center, we need to find the extension page that just opened
    const pages = await browser.pages();
    let securityCenterPage = pages.find(p => p.url().includes('security-center.html'));
    console.log('Security Center opened?', !!securityCenterPage);
    
    if (securityCenterPage) {
      console.log('--- B2, B3, B4. Security Center checks ---');
      await securityCenterPage.waitForSelector('#view-event-details.active', {timeout: 5000}).catch(() => {});
      
      const detailsText = await securityCenterPage.evaluate(() => document.getElementById('view-event-details').innerText);
      console.log('Details View Text:', detailsText.substring(0, 200).replace(/\n/g, ' '));
      
      console.log('Navigating to History...');
      await securityCenterPage.evaluate(() => {
        Array.from(document.querySelectorAll('.nav-item')).find(el => el.textContent.includes('History')).click();
      });
      await new Promise(r => setTimeout(r, 1000));
      const historyTable = await securityCenterPage.evaluate(() => document.getElementById('history-table').innerText);
      console.log('History Table headers and first row:', historyTable.substring(0, 200).replace(/\n/g, ' '));
      
      console.log('Navigating to Links...');
      await securityCenterPage.evaluate(() => {
        Array.from(document.querySelectorAll('.nav-item')).find(el => el.textContent.includes('Links')).click();
      });
      await new Promise(r => setTimeout(r, 1000));
      const linksTable = await securityCenterPage.evaluate(() => document.getElementById('link-analysis-table').innerText);
      console.log('Links Table includes invoice?', linksTable.includes('invoice'));
    }

    console.log('--- C1. File dedup & C2. Mixed ---');
    await page.evaluate(() => {
      document.querySelector('[data-testid="conversation-panel-messages"]').innerHTML = '';
      const shadow = document.getElementById('verifyfirst-overlay-container')?.shadowRoot;
      if (shadow) shadow.innerHTML = '';
    });
    
    await injectMockMessage("payment.exe", true);
    await injectMockMessage("payment.exe", true);
    await injectMockMessage("https://suspicious.example");
    
    overlayHtml = await page.evaluate(() => document.getElementById('verifyfirst-overlay-container')?.shadowRoot?.innerHTML || '');
    console.log('Overlay includes payment.exe?', overlayHtml.includes('payment.exe'));
    console.log('Overlay includes suspicious.example?', overlayHtml.includes('suspicious.example'));
    console.log('Overlay navigation present?', overlayHtml.includes('‹') && overlayHtml.includes('›'));
    
    console.log('Done.');
  } catch (e) {
    console.error('Test error:', e);
  } finally {
    await browser.close();
  }
}

runTests();
