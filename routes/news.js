const express = require('express')
const news = require('../controllers/news')

const router = express.Router()

/* GET all news listing. */

router.get('/', news.getNews)
router.get('/:id', news.getNewsById)

module.exports = router
