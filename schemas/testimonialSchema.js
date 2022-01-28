const testimonialSchema = {
  name: {
    isLength: {
      options: { min: 3, max: 64 },
    },
  },
  content: {
    isLength: {
      options: { min: 3 },
    },
  },
}

module.exports = testimonialSchema
