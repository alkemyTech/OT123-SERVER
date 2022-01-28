'use strict';
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn('Organizations', 'facebook', {
      type: Sequelize.STRING
    });
    await queryInterface.addColumn('Organizations', 'linkedin', {
      type: Sequelize.STRING
    });
    await queryInterface.addColumn('Organizations', 'instagram', {
      type: Sequelize.STRING
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('Organizations');
  }
};
