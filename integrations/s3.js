import config from '@/config'
import { S3 } from '@aws-sdk/client-s3'
import multer from 'multer'
import multerS3 from 'multer-s3'
import path from 'path'
import { v4 as uuid } from 'uuid'
import * as enums from '@/constants/enums'

class AwsS3 {
    constructor() {
        this.s3 = new S3({
            region: config.AWS_S3_REGION,
            credentials: {
                accessKeyId: config.AWS_S3_ACCESS,
                secretAccessKey: config.AWS_S3_SECRET,
            },
        })
    }

    getBucketName(type) {
        if (type.toLowerCase() !== 'public' && type.toLowerCase() !== 'private') {
            throw new TypeError('Invalid bucket type')
        }

        return config[`AWS_S3_${type.toUpperCase()}`]
    }

    getFolderName(field) {
        switch (field) {
            case 'rating':
                return config.RATINGS_IMAGES
            default:
                return 'others'
        }
    }

    getExtName(filename) {
        if (filename.endsWith('tar.gz')) {
            return '.tar.gz'
        } else if (filename.endsWith('tar.xz')) {
            return '.tar.xz'
        } else {
            return path.extname(filename)
        }
    }

    getMulterStorage(type) {
        return multerS3({
            s3: this.s3,
            bucket: this.getBucketName(type),
            contentType: multerS3.AUTO_CONTENT_TYPE,
            key: function (req, file, cb) {
                const key = `${this.getFolderName(file.fieldname)}/${req.user._id}-${uuid()}${this.getExtName(file.originalname)}`
                cb(null, key)
            }.bind(this),
        })
    }

    getFileLimits(field) {
        return {
            fileSize: config[`MAX_${field?.toUpperCase()}_FILE_SIZE`],
        }
    }

    getFileFilter(type) {
        return function (req, file, cb) {
            if (Array.isArray(type)) {
                for (const ft of type) {
                    if (file.mimetype.startsWith(ft)) {
                        return cb(null, true)
                    }
                }
            } else {
                if (file.mimetype.startsWith(type)) {
                    return cb(null, true)
                } else {
                    return cb(new Error('Invalid file type'))
                }
            }
        }
    }

    uploadFiles(bucketType, fileType, fieldName) {
        return multer({
            storage: this.getMulterStorage(bucketType),
            limits: this.getFileLimits(fieldName),
            fileFilter: this.getFileFilter(fileType),
        })
    }

    getBucketAndFileType(fieldname) {
        switch (fieldname) {
            case config.PROFILE_IMAGES:
                return {
                    filetype: 'image',
                    bucketType: 'public',
                }
            case config.COVER_IMAGES:
                return {
                    filetype: 'image',
                    bucketType: 'public',
                }
            case config.POSTATTACHMENT_IMAGES:
                return {
                    filetype: ['image', 'video'],
                    bucketType: 'public',
                }
            default:
                return {
                    filetype: '',
                    bucketType: 'public',
                }
        }
    }

    uploadFile(fieldName, type) {
        const { filetype, bucketType } = this.getBucketAndFileType(fieldName)

        switch (type) {
            case enums.AWS_FILE_TYPES.SINGLE:
                return this.uploadFiles(bucketType, filetype, fieldName).single(fieldName)
            case enums.AWS_FILE_TYPES.MULTI:
                return this.uploadFiles(bucketType, filetype, fieldName).array(fieldName)
            case enums.AWS_FILE_TYPES.FIELDS:
                return this.uploadFiles(bucketType, filetype, fieldName).fields(fieldName)
            default:
                break
        }
    }

    awsUpload(fieldName, type = enums.AWS_FILE_TYPES.SINGLE) {
        return (req, res, next) => {
            try {
                const upload = this.uploadFile(fieldName, type)
                upload(req, res, (error) => {
                    if (error) {
                        if (error.code === 'LIMIT_FILE_SIZE') {
                            return res.status(400).json({
                                success: false,
                                message: 'File is too large',
                            })
                        } else if (error.code === 'LIMIT_UNEXPECTED_FILE') {
                            return res.status(400).json({
                                success: false,
                                message: 'Invalid field type',
                            })
                        } else {
                            console.log('AwsS3.awsUpload : ', error)
                            return res.status(500).json({
                                success: false,
                                message: 'Something went wrong',
                            })
                        }
                    }
                    return next()
                })
            } catch (error) {
                console.log(error)
                return res.status(500).json({
                    success: false,
                    message: 'Something went wrong',
                })
            }
        }
    }
}

const s3 = new AwsS3()

export default s3
