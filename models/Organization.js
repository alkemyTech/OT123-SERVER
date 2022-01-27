'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Organization extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      Organization.hasMany(models.Slide, {
        foreignKey: 'organizationId'
      })
    }
  };
  Organization.init({
    name: DataTypes.STRING,
    image: DataTypes.STRING,
    phone: DataTypes.STRING,
    address: DataTypes.STRING,
    welcome_text: DataTypes.TEXT,
    facebook: DataTypes.STRING,
    linkedin: DataTypes.STRING,
    instagram: DataTypes.STRING,
  }, {
    sequelize,
    modelName: 'Organization',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    deletedAt: 'deletedAt',
    paranoid: true,
    timestamps: true,
  });
  return Organization;
};
