import isEmpty from 'is-empty'

export const pagination = (query) => {
    const page = !isEmpty(query.goto) && query.goto != '0' ? parseInt(query.goto) : parseInt(query.page) || 1
    const limit = parseInt(query.limit) || 10
    const skip = (page - 1) * limit

    return { page, limit, skip }
}
