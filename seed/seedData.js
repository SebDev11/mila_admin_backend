const User = require('../models/User');
const Campaign = require('../models/Campaign');
const Lead = require('../models/Lead');
const List = require('../models/List');
const Mail = require('../models/Mail');
const EmailActivity = require('../models/EmailActivity');
const connectDB = require('../config/database');

const seedData = async () => {
  try {
    await connectDB();

    // Clear existing data
    await User.deleteMany({});
    await Campaign.deleteMany({});
    await Lead.deleteMany({});
    await List.deleteMany({});
    await Mail.deleteMany({});
    await EmailActivity.deleteMany({});

    console.log('Cleared existing data');

    // Create sample users
    const users = await User.create([
      {
        username: 'admin',
        email: 'admin@sebastian.com',
        password: 'admin123',
        role: 'admin',
        plan: 'Pro',
        isVerified: true
      },
      {
        username: 'john_doe',
        email: 'john@example.com',
        password: 'password123',
        role: 'regular',
        plan: 'Pro',
        isVerified: true
      },
      {
        username: 'jane_smith',
        email: 'jane@example.com',
        password: 'password123',
        role: 'regular',
        plan: 'Free',
        isVerified: true
      },
      {
        username: 'bob_wilson',
        email: 'bob@example.com',
        password: 'password123',
        role: 'regular',
        plan: 'Free',
        isVerified: false
      },
      {
        username: 'alice_brown',
        email: 'alice@example.com',
        password: 'password123',
        role: 'regular',
        plan: 'Pro',
        isVerified: true
      }
    ]);

    console.log('Created users:', users.length);

    // Create sample lists
    const lists = await List.create([
      {
        name: 'Tech Leads',
        status: 'active',
        source: ['website', 'linkedin'],
        userId: users[1]._id
      },
      {
        name: 'Marketing Leads',
        status: 'active',
        source: ['linkedin', 'referral'],
        userId: users[2]._id
      }
    ]);

    console.log('Created lists:', lists.length);

    // Create sample leads
    // Create sample leads remove
    const leads = await Lead.create([
      {
        name: 'John Lead',
        firstName: 'John',
        lastName: 'Lead',
        email: 'lead1@company.com',
        title: 'CTO',
        seniority: 'C-Level',
        company: 'Tech Corp',
        companyClean: 'Tech Corp',
        companyLocation: 'San Francisco, CA',
        companyCity: 'San Francisco',
        companyCountry: 'USA',
        companyIndustry: 'Technology',
        contactCountry: 'USA',
        contactCity: 'San Francisco',
        listId: lists[0]._id
      },
      {
        name: 'Sarah Manager',
        firstName: 'Sarah',
        lastName: 'Manager',
        email: 'lead2@company.com',
        title: 'Marketing Director',
        seniority: 'Director',
        company: 'Marketing Inc',
        companyClean: 'Marketing Inc',
        companyLocation: 'New York, NY',
        companyCity: 'New York',
        companyCountry: 'USA',
        companyIndustry: 'Marketing',
        contactCountry: 'USA',
        contactCity: 'New York',
        listId: lists[0]._id
      },
      {
        name: 'Mike Director',
        firstName: 'Mike',
        lastName: 'Director',
        email: 'lead3@company.com',
        title: 'Sales Director',
        seniority: 'Director',
        company: 'Sales Co',
        companyClean: 'Sales Co',
        companyLocation: 'Chicago, IL',
        companyCity: 'Chicago',
        companyCountry: 'USA',
        companyIndustry: 'Sales',
        contactCountry: 'USA',
        contactCity: 'Chicago',
        listId: lists[1]._id
      },
      {
        name: 'Lisa CEO',
        firstName: 'Lisa',
        lastName: 'CEO',
        email: 'lead4@company.com',
        title: 'CEO',
        seniority: 'C-Level',
        company: 'Startup XYZ',
        companyClean: 'Startup XYZ',
        companyLocation: 'Austin, TX',
        companyCity: 'Austin',
        companyCountry: 'USA',
        companyIndustry: 'Startup',
        contactCountry: 'USA',
        contactCity: 'Austin',
        listId: lists[1]._id
      }
    ]);

    console.log('Created leads:', leads.length);

    // Create sample mail accounts
    const mails = await Mail.create([
      {
        provider: 'gmail',
        email: 'noreply@sebastian.com',
        status: true,
        warmUpStatus: true,
        userId: users[1]._id
      },
      {
        provider: 'gmail',
        email: 'marketing@sebastian.com',
        status: true,
        warmUpStatus: true,
        userId: users[2]._id
      }
    ]);

    console.log('Created mail accounts:', mails.length);

    // Create sample campaigns
    const campaigns = await Campaign.create([
      {
        name: 'Q3 Launch',
        status: 'active',
        language: 'English',
        toneOfVoice: 'Professional',
        showEmailAddress: true,
        unSubscribe: true,
        unSubscribeType: 'link',
        responseFrom: { time: 1, unit: 'day' },
        responseTo: { time: 7, unit: 'days' },
        sender: 'noreply@sebastian.com',
        userId: users[1]._id,
        listId: lists[0]._id
      },
      {
        name: 'Spring Promo',
        status: 'paused',
        language: 'English',
        toneOfVoice: 'Friendly',
        showEmailAddress: true,
        unSubscribe: true,
        unSubscribeType: 'link',
        responseFrom: { time: 2, unit: 'days' },
        responseTo: { time: 14, unit: 'days' },
        sender: 'marketing@sebastian.com',
        userId: users[2]._id,
        listId: lists[1]._id
      },
      {
        name: 'Welcome Series',
        status: 'completed',
        language: 'English',
        toneOfVoice: 'Welcoming',
        showEmailAddress: true,
        unSubscribe: true,
        unSubscribeType: 'link',
        responseFrom: { time: 1, unit: 'day' },
        responseTo: { time: 5, unit: 'days' },
        sender: 'noreply@sebastian.com',
        userId: users[1]._id,
        listId: lists[0]._id
      },
      {
        name: 'Product Update',
        status: 'draft',
        language: 'English',
        toneOfVoice: 'Informative',
        showEmailAddress: true,
        unSubscribe: true,
        unSubscribeType: 'link',
        responseFrom: { time: 1, unit: 'day' },
        responseTo: { time: 10, unit: 'days' },
        sender: 'noreply@sebastian.com',
        userId: users[1]._id,
        listId: lists[0]._id
      }
    ]);

    console.log('Created campaigns:', campaigns.length);

    // Create sample email activities
    const emailActivities = await EmailActivity.create([
      {
        leadId: leads[0]._id,
        campaignId: campaigns[0]._id,
        senderId: mails[0]._id,
        type: 'sent',
        subject: 'Exciting Q3 Launch - Don\'t Miss Out!',
        body: 'We\'re launching amazing new features...',
        sequenceStep: 1
      },
      {
        leadId: leads[1]._id,
        campaignId: campaigns[0]._id,
        senderId: mails[0]._id,
        type: 'sent',
        subject: 'Exciting Q3 Launch - Don\'t Miss Out!',
        body: 'We\'re launching amazing new features...',
        sequenceStep: 1
      },
      {
        leadId: leads[0]._id,
        campaignId: campaigns[0]._id,
        senderId: mails[0]._id,
        type: 'reply',
        subject: 'Re: Exciting Q3 Launch - Don\'t Miss Out!',
        body: 'This looks interesting! Tell me more...',
        sequenceStep: 2
      }
    ]);

    console.log('Created email activities:', emailActivities.length);

    console.log('Seed data created successfully!');
    console.log('\nSample data summary:');
    console.log('- Users:', users.length);
    console.log('- Lists:', lists.length);
    console.log('- Leads:', leads.length);
    console.log('- Mail accounts:', mails.length);
    console.log('- Campaigns:', campaigns.length);
    console.log('- Email activities:', emailActivities.length);
    console.log('\nYou can now test the API endpoints with this data.');

    process.exit(0);
  } catch (error) {
    console.error('Error seeding data:', error);
    process.exit(1);
  }
};

// Run seed if this file is executed directly
if (require.main === module) {
  seedData();
}

module.exports = seedData; 