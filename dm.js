const axios = require('axios')
const chalk = require('chalk')
const { gzip } = require('node-gzip')
const fs = require('fs/promises')
const os = require('os')
const puppeteer = require('puppeteer-extra')
const StealthPlugin = require('puppeteer-extra-plugin-stealth')

puppeteer.use(StealthPlugin())

let requestTiming = 0,
    config,
    baseInfo = false,
    browser,
    x5sec = {},
    timer,
    selectIndex = 0,
    log = console.log

axios.interceptors.request.use(async (conf) => {
    requestTiming = Date.now()
    return conf
})

axios.interceptors.response.use(async (response) => {
    // log(`响应URL：${chalk.green(response.config.url)}，请求耗时：${chalk.green(Date.now() - requestTiming)}ms`)
    if (response.data.ret && !response.data.ret.includes('SUCCESS::调用成功')) {
        log(chalk.red.bold(response.data.ret))
        const code = response.data.ret[0].match(/(.*)::/)[1]
        const errCode = ['B-00203-200-031', 'B-00203-100-025']
        if (code.includes('FAIL_SYS') || errCode.includes(code)) {
            process.exit(1)
        } else if (code.includes('B-00203-400-339') || code.includes('B-00203-200-009')) {
            // 存在未支付订单 等待支付后继续执行代码
            await queryOrderList(JSON.stringify({ pageSize: 20, pageNum: 1, queryType: 0 }))
        }
        return Promise.reject(response)
    } else {
        if (response.config.url.includes('getSign')) {
            if (typeof response.data.data == 'string') {
                response.data.data = formatParmas(response.data.data)
            }
        }
        return response
    }
})

// 格式化
const formatParmas = (str) => {
    str = str.replace(/^{|}$/g, '')

    const params = {}

    str.replace(/data={(.*)},|\s+/g, '')
        .split(',')
        .forEach((v) => {
            v.replace('=', (a, b, c) => {
                if (c.slice(0, b).includes('x') || ['wua', 'f-refer', 'user-agent'].includes(c.slice(0, b))) {
                    params[c.slice(0, b)] = encodeURIComponent(c.slice(b + 1))
                } else {
                    params[`x-${c.slice(0, b)}`] = encodeURIComponent(c.slice(b + 1))
                }
            })
        })

    const wua = params['wua']

    delete params['wua']

    return {
        wua,
        data: encodeURIComponent(str.match(/data=({.*}),(.*?)/)[1]),
        headers: {
            'x-sgext': params['x-sgext'],
            'f-refer': params['f-refer'],
            'x-ttid': params['x-ttid'],
            'x-app-ver': params['x-app-ver'],
            'x-sign': params['x-sign'],
            'x-sid': params['x-sid'],
            'x-c-traceid': params['x-c-traceid'],
            'x-uid': params['x-uid'],
            'x-nettype': params['x-netType'],
            'x-pv': params['x-pv'],
            'x-nq': params['x-nq'],
            'x-features': params['x-features'],
            'x-app-conf-v': params['x-app-conf-v'],
            'x-umt': params['x-umt'],
            'x-mini-wua': params['x-mini-wua'],
            'x-utdid': params['x-utdid'],
            'x-appkey': params['x-appKey'],
            'x-t': params['x-t'],
            'user-agent': params['user-agent']
        }
    }
}

// chrome path
const defaultChromeExecutablePath = () => {
    switch (os.platform()) {
        case 'win32':
            return 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
        case 'darwin':
            return '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
        case 'linux':
            return '/usr/bin/chromium-browser'
        default: {
            const chromeExists = fs.existsSync('/usr/bin/google-chrome')
            return chromeExists ? '/usr/bin/google-chrome' : '/usr/bin/google-chrome-stable'
        }
    }
}

// 打印信息
const printBaseInfo = (itemBasicInfo) => {
    const { projectTitle, cityName, venueName, priceRange, sellingStartTime, limitQuantity, performCalendar } =
        itemBasicInfo
    config.title = projectTitle
    log(`${chalk.yellow('演唱会名称：')}${chalk.green.bold(projectTitle)}`)
    log(`${chalk.yellow('销售开始时间：')}${chalk.green.bold(sellingStartTime)}`)
    log(`${chalk.yellow('每人限购：')}${chalk.green.bold(limitQuantity)}`)
    log(`${chalk.yellow('可选择场次：')}${performCalendar.map((v) => chalk.green.bold(`${v.performName}`)).join('、')}`)
    log(
        `${chalk.yellow('已选择场次：')}${performCalendar
            .filter((v) => config.currentPerformId.includes(v.performId))
            .map((v) => chalk.green.bold(`${v.performName}`))
            .join('、')}`
    )
    log(`${chalk.yellow('演唱会城市：')}${chalk.green.bold(cityName)}`)
    log(`${chalk.yellow('演唱会地址：')}${chalk.green.bold(venueName)}`)
    log(`${chalk.yellow('票价范围：')}${chalk.green.bold(priceRange)}`)
    baseInfo = true
}

// x5sec wait
const waitX5sec = async (skuId) => {
    return new Promise((resolve) => {
        const timer = setInterval(() => {
            if (x5sec[skuId]) {
                resolve(x5sec[skuId])
                clearInterval(timer)
            }
        })
    })
}

// wait promise
const wait = async (time) => {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve()
        }, time)
    })
}

// 查票详情
const getDetail = async (body) => {
    const sign = async () =>
        await axios
            .get(config.signHost, {
                params: {
                    user: config.user,
                    api: 'mtop.alibaba.detail.subpage.getdetail',
                    apiVersion: '2.0',
                    body,
                    isWua: false
                }
            })
            .catch(async () => await sign())
    const { data } = await sign()

    if (data.code === 1) {
        const res = await axios.post(
            `http://acs.m.taobao.com/gw/mtop.alibaba.detail.subpage.getdetail/2.0`,
            `data=${data.data.data}`,
            {
                headers: data.data.headers
            }
        )
        const { result } = res.data.data
        const { itemBasicInfo, perform, performCalendar } = JSON.parse(result)
        !baseInfo &&
            printBaseInfo({
                ...itemBasicInfo,
                performCalendar: performCalendar.performViews,
                limitQuantity: perform.limitQuantity
            })
        const filterSkuId = () => perform.skuList.filter((v) => v.salableQuantity > 0).map((v) => v.skuId)
        if (!config.skuId.length && !config.skuMore) {
            log(chalk.red('未填写skuId~将以有票且价位从高到低档位进行下单'))
            config.skuId = filterSkuId().slice(-1)
        } else if (config.skuMore) {
            log(chalk.red('采取多档位票价进行下单'))
            if (!config.skuId.length) config.skuId = filterSkuId()
        } else {
            selectIndex = perform.skuList.findIndex((v) => config.skuId.includes(v.skuId))
            if (+perform.skuList[selectIndex]?.salableQuantity === 0) {
                // 当前票价已经无票，自动切换下一档位票价
                log(chalk.red('选中票价已经无票，自动切换下一档位票价'))
                config.skuId = filterSkuId().slice(-1)
            }
        }
        if (!config.skuId.length) {
            log(chalk.red.bold('全部场次无票~开始等待回流票'))
            if (Date.now() - new Date(config.startTime).getTime() > 10 * 60 * 1000) {
                log(chalk.red.bold('超过10分钟停止脚本运行'))
                process.exit(1)
            }
            await wait(Math.floor(Math.random() * 1000))
            await getDetail(body)
            return
        }
        perform.skuList.forEach((item) => {
            log(
                `${chalk.yellow(`${item.priceName}：`)}${chalk.green.bold(`剩余${item.salableQuantity}张`)}${
                    Array.from(config.skuId).includes(item.skuId) ? chalk.red.bold(`（已选择）`) : ''
                }`
            )
        })
    } else {
        log(chalk.red.bold('详情获取失败'))
        process.exit(1)
    }
}

// 构建订单
const buildOrderInfo = async (body, skuId) => {
    return new Promise(async (resolve, reject) => {
        const sign = async () =>
            await axios
                .get(config.signHost, {
                    params: {
                        user: config.user,
                        api: 'mtop.trade.order.build',
                        apiVersion: '4.0',
                        body,
                        isWua: true
                    }
                })
                .catch(async () => await sign())
        const { data } = await sign()
        if (data.code === 1) {
            const func = async (opts) => {
                log(chalk.yellow.bold('开始构建订单信息'))
                if (x5sec[skuId]) {
                    opts.headers.cookie = `x5sec=${x5sec[skuId]}`
                    x5sec[skuId] = null
                }
                axios
                    .post(`http://mtop.damai.cn/gw/mtop.trade.order.build/4.0`, `wua=${opts.wua}&data=${opts.data}`, {
                        headers: opts.headers
                    })
                    .then(async (res) => {
                        const { data, endpoint, hierarchy, linkage } = res.data.data
                        delete hierarchy.root
                        delete linkage.input
                        delete linkage.request
                        const buildFields = () => {
                            const fields = [
                                'dmContactEmail',
                                'dmContactName',
                                'dmContactPhone',
                                'dmDeliveryAddress',
                                'dmDeliverySelectCard',
                                'dmEttributesHiddenBlock',
                                'dmPayType',
                                'dmViewer',
                                'item'
                            ]
                            const obj = {
                                confirmOrder_1: data.confirmOrder_1
                            }
                            for (let key in data) {
                                const s = key.split('_')[0]
                                if (fields.includes(s)) {
                                    if (s === 'dmViewer') {
                                        data[key].fields.selectedNum = config.selectedNum
                                        data[key].fields.viewerList.forEach((item) => {
                                            item.isUsed = 'true'
                                            item.used = true
                                            item.disabled = false
                                        })
                                    }
                                    obj[key] = data[key]
                                }
                            }
                            return {
                                data: obj,
                                endpoint,
                                hierarchy,
                                linkage
                            }
                        }
                        const params = buildFields()
                        const compressed = await gzip(JSON.stringify(params))
                        resolve({
                            feature: '{"gzip":"true"}',
                            params: Buffer.from(compressed).toString('base64')
                        })
                    })
                    .catch(async (error) => {
                        if (error?.message?.includes('419')) {
                            log(chalk.red.bold('开始进行绕过滑块'))
                            x5sec[skuId] = null
                            const page = await createPage(error.response.headers.location, skuId)
                            await slideValid(page, skuId)
                            await func(opts)
                        } else if (!error?.data?.ret) {
                            log(chalk.red.bold('限流~'))
                            // 重新构建抢票
                            await execute()
                        } else {
                            await wait(1000)
                            await func(opts)
                        }
                    })
            }
            await func(data.data)
        } else {
            log(chalk.red.bold('构建订单信息失败'))
            reject()
        }
    })
}

// 创建订单
const createdOrder = async (body, skuId) => {
    return new Promise(async (resolve, reject) => {
        const sign = async () =>
            await axios
                .get(config.signHost, {
                    params: {
                        user: config.user,
                        api: 'mtop.trade.order.create',
                        apiVersion: '4.0',
                        body,
                        isWua: true
                    }
                })
                .catch(async () => await sign())
        const { data } = await sign()
        if (data.code === 1) {
            const func = async (opts) => {
                log(chalk.yellow.bold('开始创建订单'))
                if (x5sec[skuId]) opts.headers.cookie = `x5sec=${x5sec[skuId]}`
                axios
                    .post(`http://mtop.damai.cn/gw/mtop.trade.order.create/4.0`, `wua=${opts.wua}&data=${opts.data}`, {
                        headers: opts.headers
                    })
                    .then(async (res) => {
                        const { alipayOrderId } = res.data.data
                        if (alipayOrderId) {
                            log(chalk.green.bold('订单创建成功'))
                            if (config.wxNotify) {
                                await axios({
                                    url: config.wxNotify,
                                    method: 'post',
                                    data: {
                                        wxId: config.wxId,
                                        message: `${config.title} 订单创建成功`
                                    },
                                    headers: {
                                        'Content-Type': 'application/json'
                                    }
                                })
                            }
                            resolve()
                        }
                    })
                    .catch(async (error) => {
                        if (error?.message?.includes('419')) {
                            log(chalk.red.bold('开始进行绕过滑块'))
                            x5sec[skuId] = null
                            const page = await createPage(error.response.headers.location, skuId)
                            await slideValid(page, skuId)
                            await func(opts)
                        } else {
                            if (error?.data?.ret && error.data.ret[0].includes('B-00203-200-008')) {
                                // 库存不足 重新构建抢票
                                await wait(Math.floor(Math.random() * 1000))
                                await execute()
                            } else if (!error.data) {
                                log(chalk.red.bold('限流~重新build抢票'))
                                // 重新构建抢票
                                await execute()
                            } else {
                                await wait(1000)
                                await func(opts)
                            }
                        }
                    })
            }
            await func(data.data)
        } else {
            log(chalk.red.bold('构建订单信息失败'))
            reject()
        }
    })
}

// 查询订单
const queryOrderList = async (body) => {
    return new Promise(async (resolve, reject) => {
        const { data } = await axios.get(config.signHost, {
            params: {
                user: config.user,
                api: 'mtop.damai.wireless.order.orderlist',
                apiVersion: '2.0',
                body,
                isWua: false
            }
        })
        if (data.code === 1) {
            const func = async (opts) => {
                log(chalk.yellow.bold('查询订单支付信息'))
                axios
                    .post(`http://mtop.damai.cn/gw/mtop.damai.wireless.order.orderlist/2.0`, `data=${opts.data}`, {
                        headers: opts.headers
                    })
                    .then(async (res) => {
                        const orderList = res.data.data.orderList
                        const waitPay = orderList.filter((item) => item.orderStatus === '待付款')
                        if (waitPay.length) {
                            waitPay.forEach((item) => {
                                log(chalk.red.bold(`${item.projectName}-${item.orderStatus}-${item.totalAmount}`))
                            })
                            log(chalk.red.bold('抢票执行结束'))
                            process.exit(1)
                        } else {
                            log(chalk.red.bold('没有待支付订单'))
                            resolve()
                        }
                    })
            }
            await func(data.data)
        } else {
            log(chalk.red.bold('查询订单信息失败'))
            reject()
        }
    })
}

// 创建browser
const createdBrowser = async () => {
    browser = await puppeteer.launch({
        headless: config.auto ? 'new' : false,
        defaultViewport: { width: 1680, height: 800 },
        executablePath: defaultChromeExecutablePath(),
        args: [`--window-size=${1680},${1080}`, '--no-sandbox', '--disable-setuid-sandbox'],
        timeout: 0
    })
}

// 创建页面
async function createPage(url, skuId) {
    let page
    if (config.skuMore) {
        const context = await browser.createIncognitoBrowserContext()
        page = await context.newPage()
    } else {
        page = await browser.newPage()
    }
    await page.setRequestInterception(true)
    page.on('request', async (interceptedRequest) => {
        if (interceptedRequest.interceptResolutionState().action === 'already-handled') return
        interceptedRequest.continue()
        const resType = interceptedRequest.resourceType()
        if (
            ['xhr'].indexOf(resType) !== -1 &&
            interceptedRequest.url().includes('report') &&
            interceptedRequest.url().includes('cookie')
        ) {
            log(chalk.green.bold(`滑块已破解，耗时：${Date.now() - requestTiming}ms`))
            x5sec[skuId] = decodeURIComponent(interceptedRequest.url()).match(/x5sec:(.*?)&/)[1]
            await page.close()
        }
    })
    await page.goto(url, { waitUntil: 'networkidle0', timeout: 0 })

    return page
}

// 滑块验证
const slideValid = async (page, skuId) => {
    requestTiming = Date.now()
    const drag = async () => {
        await page.waitForSelector('#nc_1_n1z')
        const dragBtn = await page.$('#nc_1_n1z')
        const dragSlide = await page.$('#nc_1_wrapper')
        const dragBtnPosition = await page.evaluate((element) => {
            const { x, y, width, height } = element.getBoundingClientRect()
            return { x, y, width, height }
        }, dragBtn)

        const distance = await page.evaluate(
            (element, dragBtnPosition) => {
                const { width } = element.getBoundingClientRect()
                return width - dragBtnPosition.width / 2
            },
            dragSlide,
            dragBtnPosition
        )

        const x = dragBtnPosition.x + dragBtnPosition.width / 2
        const y = dragBtnPosition.y + dragBtnPosition.height / 2
        // 滑动次数[2,3]
        const slideNum = Math.floor(Math.random() * 2 + 2)
        const getRandomNum = (n, total) => {
            const res = []
            let range = total
            let preTotal = 0
            for (let i = 0; i < n - 1; i++) {
                const item = Math.ceil(Math.random() * (range / 2))
                res.push(item)
                range -= item
                preTotal += item
            }
            res.push(total - preTotal)
            return res
        }
        // 生成随机距离
        const distanceArr = getRandomNum(slideNum, Math.floor(distance))
        await page.mouse.move(x, y)
        await page.mouse.down()
        let preDistance = x

        for (let i = 0; i < distanceArr.length; i++) {
            preDistance = preDistance + distanceArr[i]
            await page.mouse.move(preDistance, y, {
                steps: Math.floor(Math.random() * 20 + 30)
            })
        }

        await page.mouse.up()
    }
    if (config.auto) {
        do {
            try {
                ;(await page.$('.errloading')) && (await page.reload())
                !x5sec[skuId] && (await drag())
            } catch (e) {}
        } while (!x5sec[skuId])
    } else {
        return await waitX5sec(skuId)
    }
}

// 设置定时开抢时间
const setRushTobuyTime = async () => {
    return new Promise((resolve) => {
        if (config.startTime) {
            log(chalk.red.bold(`抢票任务将在${config.startTime}开始执行`))
            timer = setInterval(() => {
                const startTime = new Date(config.startTime).getTime()
                if (Date.now() >= startTime) {
                    resolve()
                    timer = null
                }
            })
        } else {
            resolve()
        }
    })
}

// 抢购
const rushTobuy = async () => {
    const promiseAll = config.skuId.map(
        (skuId) =>
            new Promise(async (resolve) => {
                // 构建订单信息
                const orderInfo = await buildOrderInfo(
                    JSON.stringify({
                        buyNow: 'true',
                        buyParam: `${config.itemId}_${config.selectedNum}_${skuId}`,
                        exParams: JSON.stringify({
                            UMPCHANNEL_DM: '10001',
                            UMPCHANNEL_TPP: '50053',
                            atomSplit: '1',
                            channel: 'damai_app',
                            coVersion: '2.0',
                            coupon: 'true',
                            seatInfo: '',
                            subChannel: '',
                            umpChannel: '10001',
                            websiteLanguage: 'zh_CN'
                        })
                    }),
                    skuId
                )
                // 创建订单
                await createdOrder(JSON.stringify(orderInfo), skuId)
                resolve()
            })
    )
    await Promise.allSettled(promiseAll)
}

// 执行
const execute = async () => {
    // 详情
    await getDetail(
        JSON.stringify({
            itemId: config.itemId,
            scenario: 'itemsku',
            bizCode: 'ali.china.damai',
            exParams: JSON.stringify({ dataType: config.dataType, dataId: config.currentPerformId[0] }),
            comboChannel: '1'
        })
    )
    // 设置定时购买
    await setRushTobuyTime()
    // 执行任务
    await rushTobuy()
}

;(async () => {
    // 读取配置信息
    config = process.env.itemId
        ? {
              itemId: process.env.itemId,
              selectedNum: process.env.selectedNum,
              skuId: JSON.parse(process.env.skuId),
              currentPerformId: JSON.parse(process.env.currentPerformId),
              dataType: +process.env.dataType,
              skuMore: JSON.parse(process.env.skuMore),
              auto: JSON.parse(process.env.auto),
              startTime: process.env.startTime,
              signHost: process.env.signHost,
              user: +process.env.user,
              wxNotify: process.env.wxNotify,
              wxId: process.env.wxId
          }
        : JSON.parse(await fs.readFile('./config.json', 'utf-8'))

    if (!config.itemId || !config.selectedNum || !config.dataType) {
        log(chalk.red.bold('未获取到配置文件'))
        process.exit(1)
    } else {
        // 提前创建无头浏览器
        !browser && (await createdBrowser())

        await execute()

        log(chalk.red.bold('抢票执行结束'))

        process.exit(1)
    }
})()
