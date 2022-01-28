const { checkSchema } = require('express-validator')
const express = require('express')
const testimonialSchema = require('../schemas/testimonialSchema')

const testimonials = require('../controllers/testimonial')

const router = express.Router()

// get all testimonials
router.get('/', testimonials.findAll)

// post a new schema
router.post('/new', checkSchema(testimonialSchema), testimonials.registerTestimonial)

module.exports = router
