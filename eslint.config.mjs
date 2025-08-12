import globals from 'globals'
import pluginJs from '@eslint/js'

export default [
    { languageOptions: { globals: globals.node }, ignores: ['constants/regex.js'] },
    pluginJs.configs.recommended,
    {
        rules: {
            'eqeqeq': 'off',
            'no-unused-vars': 'warn',
            'prefer-const': [
                'error',
                {
                    destructuring: 'any',
                    ignoreReadBeforeAssign: false,
                },
            ],
        },
    },
    {
        files: ['test/**/*.js'],
        languageOptions: {
            globals: {
                ...globals.mocha,
            },
        },
        rules: {
            'no-unused-expressions': 'off',
        },
    },
    {
        linterOptions: {
            reportUnusedDisableDirectives: 'error',
        },
    },
]
