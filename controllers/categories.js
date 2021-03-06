const { validationResult } = require('express-validator')
const db = require('../models')

const { Category } = db

exports.getAll = async (req, res) => {
  try {
    const categories = await Category.findAll({})
    res.status(200).json({
      ok: true,
      msg: 'Successful request',
      result: { categories: [...categories] },
    })
  } catch (error) {
    res.status(403).json({
      ok: false,
      msg: 'You are not authorized to view this information',
      error,
    })
  }
}

// eslint-disable-next-line consistent-return
exports.getCategory = async (req, res) => {
  const { id } = req.params
  try {
    const category = await Category.findByPk(id)

    if (!category) {
      return res.status(400).json({
        ok: false,
        msg: 'The category was not found.',
      })
    }

    res.status(200).json({
      ok: true,
      msg: 'Successful request',
      result: category,
    })
  } catch (error) {
    res.status(403).json({
      ok: false,
      msg: 'You are not authorized to view this information',
      error,
    })
  }
}

exports.getSome = async (req, res) => {
  try {
    // need to parseInt the params because when
    // passed this are strings
    const limit = parseInt(req.params.limit, 10) // limit is the number of objects that will return
    const offset = limit * parseInt(req.params.offset, 10) // offset is the number of the page

    const categories = await Category.findAndCountAll({
      limit,
      offset,
    })

    res.status(200).json({
      ok: true,
      result: categories,
    })
  } catch (err) {
    res.status(400).json({
      ok: false,
      msg: 'error to fetch categories',
      error: err,
    })
  }
  return null
}

exports.add = async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    res.status(422).json({
      ok: false,
      msg: 'ERROR VALIDATING DATA.',
      error: errors.array(),
    })
  }

  try {
    const newCategoryData = req.body
    const newCategory = await Category.create(newCategoryData)

    if (newCategory !== null) {
      res.status(201).json({
        ok: true,
        msg: 'SUCCESS CREATING NEW CATEGORY.',
        result: { category: { ...newCategory } },
      })
    } else {
      return
    }
  } catch (err) {
    res.status(400).json({
      ok: false,
      msg: 'ERROR CREATING NEW CATEGORY.',
      error: err,
    })
  }
}

exports.update = async (req, res) => {
  const { id } = req.params
  const { name } = req.body

  const category = await Category.findByPk(id)
  if (!Category) {
    return res.status(400).json({
      ok: false,
      msg: 'The category was not found.',
    })
  }
  category.name = name
  await category
    .save()
    .then((updatedCategory) => res.status(201).json({
      ok: true,
      msg: 'Category updated successfully',
      result: { category: { ...updatedCategory } },
    }))
    .catch((err) => {
      res.status(400).json({
        ok: false,
        msg: err.message,
        error: err,
      })
    })
  return null
}

exports.deleteCategory = async (req, res) => {
  const { id } = req.params
  try {
    const category = await Category.findByPk(id)
    if (!category) {
      return res.status(404).json({
        ok: false,
        msg: 'No category was found',
      })
    }
    await category
      .destroy()
    return res.status(200).json({
      ok: true,
      msg: 'category was deleted',
    })
  } catch (err) {
    res.status(400).json({
      ok: false,
      msg: err.message,
      error: err,
    })
  }
  return null
}
