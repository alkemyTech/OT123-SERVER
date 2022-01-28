const { validationResult } = require('express-validator')
const db = require('../models')

const { Testimonial } = db

exports.findAll = (req, res) => {
  Testimonial.findAll({})
    .then((data) => {
      res.status(200).json({
        ok: true,
        msg: 'Testimonials retrieved successfully',
        result: { testimonials: [...data] },
      })
    })
    .catch((error) => {
      res.status(500).json({
        ok: false,
        msg: error.message,
        error,
      })
    })
}

exports.registerTestimonial = async (req, res) => {
  // validation with express-validator
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({
      ok: false,
      msg: 'Validation error',
      error: errors.array(),
    })
  }

  return Testimonial.create({
    name: req.body.name,
    image: req.body.image,
    content: req.body.content,
  })
    .then((newTestimonial) => {
      res.status(201).json({
        ok: true,
        msg: 'Testimonial created',
        result: { testimonial: { ...newTestimonial } },
      })
    })
    .catch((err) => {
      res.status(400).json({
        ok: false,
        msg: 'This email adress is already in use',
        error: err,
      })
    })
}
