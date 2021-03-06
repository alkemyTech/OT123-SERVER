const { checkSchema } = require('express-validator')

const validate = checkSchema({
  firstName: {
    exists: true,
    notEmpty: true,
    isString: true,
    trim: true,
    isLength: { options: { min: 3, max: 24 } },
  },
  lastName: {
    exists: true,
    notEmpty: true,
    isString: true,
    trim: true,
    isLength: { options: { min: 3, max: 24 } },
  },
  email: {
    exists: true,
    notEmpty: true,
    isString: true,
    trim: true,
    isEmail: true,
  },
  password: {
    exists: true,
    notEmpty: true,
    isString: true,
    trim: true,
    isLength: { options: { min: 8, max: 24 } },
  },
})

module.exports = validate
