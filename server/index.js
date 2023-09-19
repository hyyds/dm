const path = require('path')
const http = require('http')
const { exec } = require('child_process')
const { promisify } = require('util')
const ex = promisify(exec)
const express = require('express')
const app = express()

const wait = (time) => {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve()
        }, time)
    })
}

app.use('/logs', express.static(path.resolve(__dirname, '../logs')))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

app.post('/gitPullScripts', async (req, res) => {
    const { commits } = req.body
    const obj = commits[0]
    console.log('开始同步代码!')
    const func = async () => await ex(`git pull`).catch(async () => await func())

    await func()
    console.log('同步成功!')
    res.json({ code: 1, message: '同步成功！' })
    obj &&
        obj.modified.includes('server/index.js') &&
        (await ex(`pm2 restart index.js`, {
            cwd: '/scripts/server'
        }))
})

app.post('/excutor', async (req, res) => {
    const { env } = req.body
    res.json({ code: 1, message: `开始执行！` })
    await ex(
        `node dm.js | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; fflush() }' >> ./logs/$(date +"%Y-%m-%d_%H-%M-%S").log 2>&1`,
        {
            cwd: '/dm/',
            timeout: 60000 * 10,
            env: {
                ...process.env,
                ...env
            }
        }
    )
})

// 所有路由定义完之后，最后做404处理 /
app.get('*', function (req, res) {
    res.sendFile(path.resolve(__dirname, './404.html'))
})

// your express configuration here
const httpServer = http.createServer(app)

httpServer.listen(7070, () => {
    console.log('启动成功')
})
