const axios = require('axios')
const chalk = require('chalk')
const fs = require('fs/promises')

let config,
    baseInfo = false,
    log = console.log

axios.interceptors.response.use(async (response) => {
    if (response.config.url.includes('getSign')) {
        if (typeof response.data.data == 'string') {
            response.data.data = formatParmas(response.data.data)
        }
    }
    return response
})

// 打印信息
const printBaseInfo = (itemBasicInfo) => {
    const { projectTitle, cityName, venueName, priceRange, sellingStartTime, limitQuantity, performCalendar } =
        itemBasicInfo
    log(`${chalk.yellow('演唱会名称：')}${chalk.green.bold(projectTitle)}`)
    log(`${chalk.yellow('销售开始时间：')}${chalk.green.bold(sellingStartTime)}`)
    log(`${chalk.yellow('每人限购：')}${chalk.green.bold(limitQuantity)}`)
    log(
        `${chalk.yellow('可选择场次：')}${performCalendar
            .map((v) => chalk.green.bold(`${v.performName}-${v.performId}`))
            .join('、')}`
    )
    log(
        `${chalk.yellow('已选择场次：')}${performCalendar
            .filter((v) => config.currentPerformId.includes(v.performId))
            .map((v) => chalk.green.bold(`${v.performName}-${v.performId}`))
            .join('、')}`
    )
    log(`${chalk.yellow('演唱会城市：')}${chalk.green.bold(cityName)}`)
    log(`${chalk.yellow('演唱会地址：')}${chalk.green.bold(venueName)}`)
    log(`${chalk.yellow('票价范围：')}${chalk.green.bold(priceRange)}`)
    baseInfo = true
}

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

// 查票详情
const getDetail = async (body) => {
    const { data } = await axios.get(`http://192.168.0.74:8888/getSign`, {
        params: {
            api: 'mtop.alibaba.detail.subpage.getdetail',
            apiVersion: '2.0',
            body,
            isWua: false
        }
    })
    if (data.code === 1) {
        axios
            .post(`http://acs.m.taobao.com/gw/mtop.alibaba.detail.subpage.getdetail/2.0`, `data=${data.data.data}`, {
                headers: data.data.headers
            })
            .then((res) => {
                const { result } = res.data.data
                console.log(res.data)
                return
                const { itemBasicInfo, perform, performCalendar } = JSON.parse(result)
                !baseInfo &&
                    printBaseInfo({
                        ...itemBasicInfo,
                        performCalendar: performCalendar?.performViews,
                        limitQuantity: perform.limitQuantity
                    })
                perform.skuList.forEach((item) => {
                    log(
                        `${chalk.yellow(`${item.priceName}：`)}${chalk.green.bold(
                            `剩余${item.salableQuantity}张、sku=${item.skuId}`
                        )}`
                    )
                })
            })
    } else {
        log(chalk.red.bold('详情获取失败'))
        process.exit(1)
    }
}

;(async () => {
    // 读取配置信息
    config = JSON.parse(await fs.readFile('./config.json', 'utf-8'))

    if (!config.itemId || !config.selectedNum || !config.dataType) {
        log(chalk.red.bold('未获取到配置文件'))
        process.exit(1)
    } else {
        const excute = async () => {
            // // 开始获取详情
            await getDetail(
                JSON.stringify({
                    itemId: config.itemId,
                    scenario: 'itemsku',
                    bizCode: 'ali.china.damai',
                    exParams: JSON.stringify({ dataType: config.dataType, dataId: config.currentPerformId[0] }),
                    comboChannel: '1'
                })
            )
        }
        await excute()
    }
})()
