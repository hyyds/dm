const frida = require('frida')
const chalk = require('chalk')
const express = require('express')
const app = express()
const http = require('http')
const source = `
rpc.exports = {
     getSign(api, apiVersion, body, isWua) {
        return new Promise((resolve) => {
            Java.perform(function () {
                // 引入Java中的类
                const MtopRequest = Java.use('mtopsdk.mtop.domain.MtopRequest')
                const MtopBusiness = Java.use('com.taobao.tao.remotebusiness.MtopBusiness')
                const MethodEnum = Java.use('mtopsdk.mtop.domain.MethodEnum')
                const System = Java.use('java.lang.System')
                const ApiID = Java.use('mtopsdk.mtop.common.ApiID')
                const MtopStatistics = Java.use('mtopsdk.mtop.util.MtopStatistics')
                const InnerProtocolParamBuilderImpl = Java.use(
                    'mtopsdk.mtop.protocol.builder.impl.InnerProtocolParamBuilderImpl'
                )
                const MtopUtils = Java.use('mtopsdk.common.util.MtopUtils')
                const HashMap2Str = (params_hm) => {
                    const HashMap = Java.use('java.util.HashMap')
                    const args_map = Java.cast(params_hm, HashMap)
                    return args_map.toString()
                }
    
                // create MtopRequest
                const myMtopRequest = MtopRequest.$new()
                myMtopRequest.setApiName(api)
                myMtopRequest.setData(body)
                myMtopRequest.setNeedEcode(true)
                myMtopRequest.setNeedSession(true)
                myMtopRequest.setVersion(apiVersion)
    
                // create MtopBusiness
                const myMtopBusiness = MtopBusiness.build(myMtopRequest)
                if (isWua === 'true') myMtopBusiness.useWua()
                myMtopBusiness.reqMethod(MethodEnum.POST.value)
                myMtopBusiness.setCustomDomain('mtop.damai.cn')
                myMtopBusiness.setBizId(24)
                myMtopBusiness.setErrorNotifyAfterCache(true)
                myMtopBusiness.reqStartTime = System.currentTimeMillis()
                myMtopBusiness.isCancelled = false
                myMtopBusiness.isCached = false
                myMtopBusiness.clazz = null
                myMtopBusiness.requestType = 0
                myMtopBusiness.requestContext = null
                myMtopBusiness.mtopCommitStatData(false)
                myMtopBusiness.sendStartTime = System.currentTimeMillis()
    
                const createListenerProxy = myMtopBusiness.$super.createListenerProxy(myMtopBusiness.$super.listener.value)
                const createMtopContext = myMtopBusiness.createMtopContext(createListenerProxy)
                createMtopContext.stats.value = MtopStatistics.$new(null, null)
                myMtopBusiness.$super.mtopContext.value = createMtopContext
                createMtopContext.apiId.value = ApiID.$new(null, createMtopContext)
    
                const myMtopContext = createMtopContext
                myMtopContext.mtopRequest.value = myMtopRequest
                const myInnerProtocolParamBuilderImpl = InnerProtocolParamBuilderImpl.$new()
                const res = myInnerProtocolParamBuilderImpl.buildParams(myMtopContext)
    
                const mtop = myMtopContext.mtopInstance.value
                const utdid = mtop.getMtopConfig().utdid.value
                const aa = MtopUtils.createIntSeqNo() % 10000
                const xctraceid = utdid + System.currentTimeMillis() + '0' + aa + '1' + mtop.getMtopConfig().processId.value
               
                const sign = HashMap2Str(res).replace('x-c-traceid=null', \`x-c-traceid=\${xctraceid}\`)  
                resolve(sign)
            })
        })
    }
};
`

app.use(express.json())
app.use(express.urlencoded({ extended: false }))

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

let func = []

app.get('/getSign', async (req, res) => {
    const { api, apiVersion, body, isWua, user } = req.query
    try {
        const sign = await func[user].getSign(api, apiVersion, body, isWua)
        const obj = formatParmas(sign)
        res.json({ code: 1, data: obj, message: 'sucess' })
    } catch (e) {
        res.json({ code: 0, message: '签名获取失败' })
    }
})
async function hook() {
    const device = await frida.getUsbDevice()
    const process = await device.enumerateProcesses()
    const targetProcess = process.filter((proc) => proc.name === 'cn.damai' || proc.name.includes('大麦'))
    if (!targetProcess) {
        console.error(`Process cn.damai not found.`)
        return
    }
    console.log(targetProcess)
    for (let i = 0; i < targetProcess.length; i++) {
        const session = await device.attach(targetProcess[i].pid)
        const script = await session.createScript(source)
        await script.load()
        func.push(script.exports)
    }
    console.log(chalk.green.bold('签名服务搭建success'))
}

const httpServer = http.createServer(app)
httpServer.listen(8888, () => hook())
