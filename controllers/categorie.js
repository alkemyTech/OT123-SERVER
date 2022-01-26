const db = require('../models')

const { Categorie } = db

exports.findAll = async (req, res) => {
  try {
    const categories = await Categorie.findAll({})
    res.status(200).json({
      ok: true,
      msg: 'Successful request',
      result: [...categories],
    })
  } catch (error) {
    res.status(403).json({
      ok: false,
      msg: 'You are not authorized to view this information',
      error,
    })
  }
}
