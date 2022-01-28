const express = require('express')

const router = express.Router()

const { createActivity, getActivities } = require('../controllers/activities')

const validateActivities = require('../middlewares/validate-activities')

/* GET activities page. */
router.get('/', getActivities)

router.post('/', validateActivities, createActivity)

module.exports = router
