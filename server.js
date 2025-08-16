/* Package Imports */
import http from 'http'
import express from 'express'
import { json, urlencoded } from 'body-parser'
import cookieParser from 'cookie-parser'
import ip from 'ip'
import frameGuard from 'frameguard'
import passport from 'passport'
import cors from 'cors'
import morgan from 'morgan'

import connectDatabase from '@/database/connection'
import config from '@/config'

import router from '@/routes'

const app = express()

app.use(
    cors({
        origin: config.CORS_ORIGIN,
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    }),
)

app.use(json({ limit: '16kb' }))
app.use(urlencoded({ extended: true }))
app.use(cookieParser())
app.use(frameGuard({ action: 'deny' }))
app.use(morgan('dev'))

app.use(passport.initialize())
// require('@/security/passport').userAuthStrategy(passport)

const serverIP = ip.address()
console.log(`\x1b[95mSERVER IP: ${serverIP}`)

app.get('/', (req, res) => res.json({ status: 'UP', message: 'Server runs' }))
app.use('/api', router)

const server = http.createServer(app)

connectDatabase((isConnect) => {
    if (isConnect) {
        server.listen(config.PORT, () => {
            // new socket.SocketInstance(server);
            console.log(`\x1b[33mServer runs in port ${config.PORT}...`)
            console.log(`\x1b[38;5;201mAPI HOST - http://${serverIP}:${config.PORT} or http://127.0.0.1:${config.PORT} or ${config.API_HOST} \n`)
        })
    }
})
