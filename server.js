const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { User, AuthToken } = require('./models');

dotenv.config();

const app = express();
app.use(express.json());

// MongoDB connection setup
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// GraphQL schema definitions
const { GraphQLObjectType, GraphQLSchema, GraphQLString, GraphQLList, GraphQLNonNull } = require('graphql');

// User type for GraphQL
const UserType = new GraphQLObjectType({
  name: 'UserType',
  fields: () => ({
    id: { type: GraphQLString },
    username: { type: GraphQLString },
    email: { type: GraphQLString },
  }),
});

// AuthToken type for GraphQL
const AuthTokenType = new GraphQLObjectType({
  name: 'AuthTokenType',
  fields: () => ({
    token: { type: GraphQLString },
    expiresAt: { type: GraphQLString },
  }),
});

// Root query for fetching users
const RootQuery = new GraphQLObjectType({
  name: 'RootQuery',
  fields: {
    getAllUsers: {
      type: new GraphQLList(UserType),
      resolve: async () => await User.find(),
    },
    getUserByEmail: {
      type: UserType,
      args: {
        email: { type: GraphQLNonNull(GraphQLString) },
      },
      resolve: async (parent, { email }) => await User.findOne({ email }),
    },
  },
});

// Mutations for user management and authentication
const Mutation = new GraphQLObjectType({
  name: 'Mutation',
  fields: {
    registerUser: {
      type: UserType,
      args: {
        username: { type: GraphQLNonNull(GraphQLString) },
        email: { type: GraphQLNonNull(GraphQLString) },
        password: { type: GraphQLNonNull(GraphQLString) },
      },
      resolve: async (parent, { username, email, password }) => {
        const existingUser = await User.findOne({ email });
        if (existingUser) throw new Error('Email already exists');

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, hashedPassword });
        return await newUser.save();
      },
    },
    loginUser: {
      type: AuthTokenType,
      args: {
        email: { type: GraphQLNonNull(GraphQLString) },
        password: { type: GraphQLNonNull(GraphQLString) },
      },
      resolve: async (parent, { email, password }) => {
        const user = await User.findOne({ email });
        if (!user) throw new Error('User not found');

        const isValidPassword = await bcrypt.compare(password, user.hashedPassword);
        if (!isValidPassword) throw new Error('Invalid credentials');

        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const expiresAt = new Date(new Date().getTime() + 3600 * 1000);  // 1 hour expiry time

        // Save the token and expiration time in the AuthToken model
        const authToken = new AuthToken({ userId: user.id, token, expiresAt });
        await authToken.save();

        return { token, expiresAt: expiresAt.toISOString() };
      },
    },
    logoutUser: {
      type: GraphQLString,
      args: {
        token: { type: GraphQLNonNull(GraphQLString) },
      },
      resolve: async (parent, { token }) => {
        await AuthToken.deleteOne({ token });
        return 'Logged out successfully';
      },
    },
  },
});

// GraphQL Schema
const schema = new GraphQLSchema({
  query: RootQuery,
  mutation: Mutation,
});

// Set up GraphQL endpoint
app.use('/graphql', graphqlHTTP({
  schema,
  graphiql: true,
}));

// Start the server
app.listen(process.env.PORT || 4000, () => {
  console.log(`Server running on port ${process.env.PORT || 4000}`);
});
