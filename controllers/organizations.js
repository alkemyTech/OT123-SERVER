const { Organization } = require('../models')

exports.byOrganizationID = async (req, res) => {
  const orgID = req.params.id

  try {
    const organization = await Organization.findOne({ where: { id: orgID } })

    if (organization !== null) {
      res.status(200).json({
        ok: true,
        msg: 'SUCCESS FETCHING DATA.',
        result: {
          publicData: {
            name: organization.name,
            image: organization.image,
            phone: organization.phone,
            address: organization.address,
            welcomeText: organization.welcome_text,
            facebook: organization.facebook,
            linkedin: organization.linkedin,
            instagram: organization.instagram,
          },
        },
      })
    } else {
      res.status(404).json({
        ok: false,
        msg: `THERE IS NO ORGANIZATION WITH THIS ID (${orgID}).`,
      })
    }
  } catch (err) {
    res.status(400).json({
      ok: false,
      msg: 'ERROR FETCHING DATA.',
      error: err,
    })
  }
}
