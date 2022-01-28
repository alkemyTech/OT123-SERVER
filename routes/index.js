const express = require('express')

const pingRouter = require('./ping')
const usersRouter = require('./users')
const activitiesRouter = require('./activities')
const organizationsRouter = require('./organizations')
const categoriesRouter = require('./categories')

const router = new express.Router()

router.use('/ping', pingRouter)
router.use('/users', usersRouter)
router.use('/organizations', organizationsRouter)
router.use('/categories', categoriesRouter)
router.use('/activities', activitiesRouter)

module.exports = router
