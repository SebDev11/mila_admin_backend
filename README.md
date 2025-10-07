# SebastianAdmin Backend API

A Node.js backend API for the SebastianAdmin application, built with Express.js and MongoDB.

## Features

- **User Management**: CRUD operations for users with role-based access
- **Campaign Management**: Email campaign creation, tracking, and analytics
- **Lead Management**: Lead tracking and status management
- **Analytics & Statistics**: Dashboard metrics and reporting
- **Billing & Subscriptions**: Plan management and payment processing
- **RESTful API**: Clean, well-documented endpoints
- **Data Validation**: Input validation and error handling
- **Security**: Password hashing, CORS, and security headers

## Tech Stack

- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **MongoDB** - Database
- **Mongoose** - ODM for MongoDB
- **bcryptjs** - Password hashing
- **express-validator** - Input validation
- **helmet** - Security headers
- **cors** - Cross-origin resource sharing

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (local installation or MongoDB Atlas)
- npm or yarn

## Installation

1. **Clone the repository and navigate to the backend directory:**
   ```bash
   cd backend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Create environment file:**
   Create a `.env` file in the backend directory with the following variables:
   ```
   PORT=5000
   NODE_ENV=development
   MONGODB_URI=mongodb://localhost:27017/sebastian-admin
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
   JWT_EXPIRES_IN=7d
   ```

4. **Start MongoDB:**
   Make sure MongoDB is running on your system or use MongoDB Atlas.

5. **Seed the database (optional):**
   ```bash
   node seed/seedData.js
   ```

6. **Start the server:**
   ```bash
   # Development mode with auto-restart
   npm run dev
   
   # Production mode
   npm start
   ```

The API will be available at `http://localhost:5000/api`

## API Endpoints

### Health Check
- `GET /api/health` - Check API status

### Users
- `GET /api/users` - Get all users (with optional filters)
- `GET /api/users/:id` - Get user by ID
- `POST /api/users` - Create new user
- `PATCH /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user
- `GET /api/users/stats/overview` - Get user statistics

### Campaigns
- `GET /api/campaigns` - Get all campaigns (with optional status filter)
- `GET /api/campaigns/:id` - Get campaign by ID
- `POST /api/campaigns` - Create new campaign
- `PATCH /api/campaigns/:id` - Update campaign
- `DELETE /api/campaigns/:id` - Delete campaign
- `PATCH /api/campaigns/:id/metrics` - Update campaign metrics
- `GET /api/campaigns/stats/overview` - Get campaign statistics

### Statistics
- `GET /api/stats` - Get overall dashboard statistics
- `GET /api/stats/weekly-engagement` - Get weekly email engagement data
- `GET /api/stats/user-growth` - Get user growth statistics
- `GET /api/stats/campaign-performance` - Get campaign performance stats
- `GET /api/stats/lead-conversion` - Get lead conversion statistics

### Billing
- `GET /api/billing` - Get billing information for all users
- `GET /api/billing/user/:userId` - Get billing information for specific user
- `PATCH /api/billing/user/:userId/plan` - Update user plan
- `GET /api/billing/analytics` - Get subscription analytics
- `POST /api/billing/process-payment` - Process payment (mock)

## Sample Data

The seed script creates the following sample data:

### Users
- Admin user (admin@sebastian.com)
- Regular users with different plans and verification statuses

### Campaigns
- Active, paused, completed, and draft campaigns
- Various engagement metrics and email statistics

### Leads
- Leads in different stages (new, contacted, qualified, converted)
- Different sources and tags

## Database Models

### User
- username, email, password
- role (admin/regular), plan (Free/Pro)
- verification and active status
- timestamps

### Campaign
- name, status, sender email
- leads array, engagement metrics
- email content and scheduling
- createdBy reference

### Lead
- email, name, company
- status, source, tags
- notes and contact history
- createdBy reference

## Error Handling

The API includes comprehensive error handling:
- Validation errors with detailed messages
- Database connection errors
- 404 for missing resources
- 500 for server errors
- Proper HTTP status codes

## Security Features

- Password hashing with bcrypt
- CORS configuration
- Security headers with helmet
- Input validation and sanitization
- Error message sanitization in production

## Development

### Project Structure
```
backend/
├── config/
│   └── database.js
├── models/
│   ├── User.js
│   ├── Campaign.js
│   └── Lead.js
├── routes/
│   ├── users.js
│   ├── campaigns.js
│   ├── stats.js
│   └── billing.js
├── seed/
│   └── seedData.js
├── server.js
├── package.json
└── README.md
```

### Adding New Features

1. Create model in `models/` directory
2. Create routes in `routes/` directory
3. Add route to `server.js`
4. Update seed data if needed
5. Test endpoints

## Testing the API

You can test the API using tools like:
- Postman
- Insomnia
- curl commands
- Frontend application

### Example curl commands:

```bash
# Get all users
curl http://localhost:5000/api/users

# Get dashboard stats
curl http://localhost:5000/api/stats

# Get campaigns
curl http://localhost:5000/api/campaigns

# Create a new user
curl -X POST http://localhost:5000/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "role": "regular",
    "plan": "Free"
  }'
```

## Production Deployment

For production deployment:

1. Set `NODE_ENV=production`
2. Use a strong JWT secret
3. Configure MongoDB Atlas or production MongoDB
4. Set up proper environment variables
5. Use a process manager like PM2
6. Set up reverse proxy (nginx)
7. Configure SSL/TLS certificates

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the ISC License. 