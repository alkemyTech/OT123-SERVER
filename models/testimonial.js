'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Testimonial extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      Testimonial.belongsTo(models.User, {
        foreignKey: 'userId',
        as: 'users'
      })
    }
  };
  Testimonial.init({
    content: DataTypes.STRING,
    userId: {
      type: DataTypes.INTEGER,
    },
    deletedAt: DataTypes.DATE
  }, {
    sequelize,
    modelName: 'Testimonial',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    deletedAt: 'deletedAt',
    paranoid: true,
    timestamps: true,
  });
  return Testimonial;
};