import isEmpty from 'is-empty'

export const userInfo = async (req, res) => {
    try {
        const { user } = req

        if (isEmpty(user)) {
            return res.status(200).json({ success: true, data: {} })
        }

        const formattedData = {
            _id: user._id,
            organizationId: user?.organizationId || null,
            role: user.role,
        }

        return res.status(200).json({ success: true, data: formattedData })
    } catch (error) {
        console.error('error: ', error)
        return res.status(500).json({ success: false, message: 'Something went wrong' })
    }
}
