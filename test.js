/**
 * @ Author: hc
 * @ Create Time: 2022/9/7 17:50
 * @ Modified by: hc
 * @ Modified time: 2022/9/7 17:50
 * @ Description: 指令
 */

const puppeteer = require('puppeteer')
const antibotbrowser = require('antibotbrowser')

// const StealthPlugin = require('puppeteer-extra-plugin-stealth')

// puppeteer.use(StealthPlugin())
/**
 * 获取指令
 */
async function moviceBot() {
    const createdBrowser = async () => {
        const antibrowser = await antibotbrowser.startbrowser()
        browser = await puppeteer.connect({ browserWSEndpoint: antibrowser.websokcet })
        // browser = await puppeteer.launch({
        //     headless: false,
        //     defaultViewport: { width: 1680, height: 800 },
        //     args: [`--window-size=${1680},${1080}`, '--no-sandbox', '--disable-setuid-sandbox'],
        //     timeout: 0
        // })
    }
    async function createPage(url) {
        let [page] = await browser.pages()
        // const context = await browser.createIncognitoBrowserContext()
        // const page = await context.newPage()
        // await page.setUserAgent(
        //     'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        // )
        await page.goto(url, { waitUntil: 'networkidle0', timeout: 0 })
        return page
    }

    await createdBrowser()

    const page = await createPage(`https://svip.bljiex.cc/so.php?wd=完美世界`)

    const verifyCf = async () => {
        if ((await page.title()).includes('moment')) {
            try {
                await page.waitForSelector('#turnstile-wrapper')
            } catch (e) {
                return Promise.resolve()
            }
            await page.waitForTimeout(5000)
            const frame = page.frames().find((frame) => frame.url().includes('cloudflare'))
            if (frame) {
                await frame.waitForSelector('input')
                await frame.click('input[type="checkbox"]')
            }
            await verifyCf()
        } else {
            await Promise.resolve()
        }
    }

    await verifyCf()

    // const elementHandle = await page.waitForSelector('iframe')

    console.log('进来了', 1)

    // const frame = await elementHandle.contentFrame()

    const s = await page.$$('#main a')

    if (!s.length) {
        this.ws.send(sendTxtMsg(this.wxId, `没有搜索到你想看的~输入其他试试。`))
        await browser.close()
        this.callback = null
        return
    }
    let hrefList = ``

    for (let i = 0; i < s.length; i++) {
        const href = await page.evaluateHandle((el) => el.getAttribute('href'), s[i])
        const text = await href.jsonValue()
        hrefList += `https://jd-bus.icu/video/${text.replace(/\.\/\?/, '')}\n`
    }
    this.ws.send(sendTxtMsg(this.wxId, `剧名：${this.content}\n${hrefList}`))
    await browser.close()
    this.callback = null
}

moviceBot()
