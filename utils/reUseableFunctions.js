import crypto from 'crypto'

export function generateOTP() {
    return crypto.randomInt(100000, 999999).toString()
}

export function generateRandomNumbers() {
    return crypto.randomInt(10000, 99999).toString()
}

export function discountPrice(discount = 0, listPrice = 0) {
    const price = (discount / 100) * listPrice
    return price
}

export function ratingPercentage(starCount, totalCount) {
    const result = (starCount / totalCount) * 100
    return result
}
