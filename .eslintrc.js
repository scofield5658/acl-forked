module.exports = {
  "parser": "babel-eslint",
  extends: 'airbnb-base',
  root: true,
  parserOptions: {
      sourceType: 'module'
  },
  env: {
      browser: true,
  },
  rules: {
    "indent": ["error", 2],
    "quotes": ["error"],
    "semi": ["error", "always"],
    "no-console": 0,
    "arrow-parens": 0,
    "array-bracket-spacing": "error",
    "object-curly-spacing": "error",
    "comma-spacing": "error",
    "func-names": 0,
    "prefer-rest-params": 0,
    "one-var": 0,
    "no-param-reassign": 0,
    "no-use-before-define": 0,
    "no-underscore-dangle": 0,
    "no-shadow": 0,
    "max-len": 0,
    "no-proto": 0,
    "no-unused-vars": 0,
    "no-multi-assign": 0,
    "no-bitwise": 0,
    "no-restricted-properties": 0,
    "no-cond-assign": 0,
    "global-require": 0,
    "no-restricted-syntax": 0,
    "no-prototype-builtins": 0,
    "prefer-destructuring": 0,
    "no-unused-expressions": 0
  }
}
