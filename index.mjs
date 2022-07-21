import process from 'node:process'
import { readFileSync } from 'node:fs'
import jwt from 'jsonwebtoken'
import pino from 'pino'
import pretty from 'pino-pretty'
import minimist from 'minimist'
import fetch from 'node-fetch'

const argv = minimist(process.argv.slice(2))

const logger = pino(pretty())

const { privateKey, keyId, teamId, clientId, authorizationCode } = argv

function validateArguments () {
  if (!authorizationCode) {
    logger.error('authorizationCode is required')
    process.exit(1)
  }

  if (!clientId) {
    logger.error('clientId is required')
    process.exit(1)
  }

  if (!teamId) {
    logger.error('--teamId is required')
    process.exit(1)
  }

  if (!privateKey) {
    logger.error('--privateKey is required')
    process.exit(1)
  }

  if (!keyId) {
    logger.error('--keyId is required')
    process.exit(1)
  }
}

validateArguments()

const _privateKey = readFileSync(privateKey)

const now = Math.floor(Date.now() / 1000)

/**
 * 지금으로 부터 5분뒤 만료되는 clientSecret을 생성한다.
 */
const clientSecret = jwt.sign({
  iss: teamId,
  iat: now,
  exp: now + 300,
  aud: 'https://appleid.apple.com',
  sub: clientId
}, _privateKey, { algorithm: 'ES256', keyid: keyId })

logger.info({
  clientSecret
}, 'clientSecret')

/**
 * Apple Public Keys를 가져온다.
 */
const publicKeys = await fetch('https://appleid.apple.com/auth/keys', {
  headers: {
    'Content-Type': 'application/json'
  }
})

const publicKeysJsonObject = await publicKeys.json()

logger.info(publicKeysJsonObject, 'publicKeys')

/**
 * AuthorizationCode를 사용하여 토큰을 발급받는다.
 */
const generateTokens = await fetch('https://appleid.apple.com/auth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: `client_id=${clientId}&client_secret=${clientSecret}&code=${authorizationCode}&grant_type=authorization_code`
})

const generateTokensJsonObject = await generateTokens.json()

logger.info(generateTokensJsonObject, 'generateTokens')

/**
 * 발급 받은 토큰을 사용하여 사용자 정보를 가져온다.
 */
const validateTokens = await fetch('https://appleid.apple.com/auth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: `client_id=${clientId}&client_secret=${clientSecret}&refresh_token=${generateTokensJsonObject.refresh_token}&grant_type=refresh_token`
})

const validateTokensJsonObject = await validateTokens.json()

logger.info(validateTokensJsonObject, 'validateTokens')

/**
 * 발급 받은 토큰을 취소한다.
 */
const revokeTokens = await fetch('https://appleid.apple.com/auth/revoke', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: `client_id=${clientId}&client_secret=${clientSecret}&token=${generateTokensJsonObject.refresh_token}&token_type_hint=refresh_token`
})

logger.info({
  status: revokeTokens.status
}, 'revokeTokens')
