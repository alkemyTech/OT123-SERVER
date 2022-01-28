const models = require('../models')

const Entries = models.Entry

exports.getNews = async (req, res) => {
  try {
    const news = await Entries.findAll({
      attributes: ['name', 'image', 'createdAt'],
      where: {
        type: 'news',
      },
    })
    res.status(200).json({
      ok: true,
      msg: 'Fetched news successfully.',
      result: { news: [...news] },
    })
  } catch (error) {
    res.status(403).json({
      ok: false,
      msg: 'error to fetch Entries',
      error,
    })
  }
}

exports.getNewsById = async (req, res) => {
  try {
    const news = await Entries.findById(req.params.id)
    res.status(200).json({
      ok: true,
      msg: 'Fetched news successfully.',
      result: { news: [...news] },
    })
  } catch (error) {
    res.status(403).json({
      ok: false,
      msg: 'error to fetch Entries',
      error,
    })
  }
}
