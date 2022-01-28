const express = require('express')

const router = express.Router()
const controller = require('../controllers/organizations')

router.get('/:id/public', controller.byOrganizationID)

module.exports = router
