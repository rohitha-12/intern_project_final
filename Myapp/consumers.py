# myapp/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import ChatRoom, Message, UserMembership, AdminProfile
from django.contrib.auth import get_user_model

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.room_name}'

        self.user = self.scope['user']
        if not self.user.is_authenticated:
            await self.close()
            return

        # Check membership status from DB
        self.is_member = await self.check_membership(self.user)

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

        # Send initial status to client
        await self.send(json.dumps({
            'type': 'connection_established',
            'username': self.user.username,
            'is_member': self.is_member,
            'admin_display_name': await self.get_admin_display_name(self.user)
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    async def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get('action')

        # Only members can send messages or perform chat actions
        if not self.is_member:
            await self.send(json.dumps({'error': 'Membership required to send messages.'}))
            return

        if action == 'send_message':
            content = data.get('content')
            if content:
                message = await self.create_message(self.user, self.room_name, content)
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message_id': message.id,
                        'username': self.user.username,
                        'content': content,
                        'timestamp': message.timestamp.isoformat(),
                        'is_pinned': message.is_pinned,
                    }
                )
        elif action == 'pin_message':
            # Admin only
            if await self.is_admin(self.user):
                message_id = data.get('message_id')
                if message_id:
                    await self.pin_unpin_message(message_id, True)
                    await self.channel_layer.group_send(
                        self.room_group_name,
                        {
                            'type': 'message_pinned',
                            'message_id': message_id,
                            'pinned_by': self.user.username
                        }
                    )
            else:
                await self.send(json.dumps({'error': 'Only admins can pin messages.'}))
        elif action == 'unpin_message':
            # Admin only
            if await self.is_admin(self.user):
                message_id = data.get('message_id')
                if message_id:
                    await self.pin_unpin_message(message_id, False)
                    await self.channel_layer.group_send(
                        self.room_group_name,
                        {
                            'type': 'message_unpinned',
                            'message_id': message_id,
                            'unpinned_by': self.user.username
                        }
                    )
            else:
                await self.send(json.dumps({'error': 'Only admins can unpin messages.'}))
        elif action == 'delete_message':
            # Admin can delete any, user can delete own message (later)
            message_id = data.get('message_id')
            if message_id:
                can_delete = False
                if await self.is_admin(self.user):
                    can_delete = True
                else:
                    # Later: implement user own message deletion permission
                    can_delete = False

                if can_delete:
                    await self.delete_message(message_id)
                    await self.channel_layer.group_send(
                        self.room_group_name,
                        {
                            'type': 'message_deleted',
                            'message_id': message_id,
                            'deleted_by': self.user.username
                        }
                    )
                else:
                    await self.send(json.dumps({'error': 'Permission denied to delete message.'}))
        elif action == 'poll_create':
            # Admin only - placeholder for poll creation
            if await self.is_admin(self.user):
                # Implement poll creation logic here in future
                await self.send(json.dumps({'info': 'Poll feature coming soon.'}))
            else:
                await self.send(json.dumps({'error': 'Only admins can create polls.'}))

    # Handlers for group_send events:

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message_id': event['message_id'],
            'username': event['username'],
            'content': event['content'],
            'timestamp': event['timestamp'],
            'is_pinned': event['is_pinned'],
        }))

    async def message_pinned(self, event):
        await self.send(text_data=json.dumps({
            'type': 'message_pinned',
            'message_id': event['message_id'],
            'pinned_by': event['pinned_by']
        }))

    async def message_unpinned(self, event):
        await self.send(text_data=json.dumps({
            'type': 'message_unpinned',
            'message_id': event['message_id'],
            'unpinned_by': event['unpinned_by']
        }))

    async def message_deleted(self, event):
        await self.send(text_data=json.dumps({
            'type': 'message_deleted',
            'message_id': event['message_id'],
            'deleted_by': event['deleted_by']
        }))

    # Database helper methods

    @database_sync_to_async
    def check_membership(self, user):
        try:
            membership = UserMembership.objects.get(user=user)
            return membership.is_member
        except UserMembership.DoesNotExist:
            return False

    @database_sync_to_async
    def create_message(self, user, room_name, content):
        room, _ = ChatRoom.objects.get_or_create(name=room_name)
        message = Message.objects.create(user=user, room=room, content=content)
        return message

    @database_sync_to_async
    def is_admin(self, user):
        # You can improve this based on your admin model/permissions
        return user.is_staff or AdminProfile.objects.filter(user=user).exists()

    @database_sync_to_async
    def pin_unpin_message(self, message_id, pin=True):
        try:
            message = Message.objects.get(id=message_id)
            message.is_pinned = pin
            message.save()
            return True
        except Message.DoesNotExist:
            return False

    @database_sync_to_async
    def delete_message(self, message_id):
        try:
            message = Message.objects.get(id=message_id)
            message.delete()
            return True
        except Message.DoesNotExist:
            return False

    @database_sync_to_async
    def get_admin_display_name(self, user):
        try:
            admin_profile = AdminProfile.objects.get(user=user)
            return admin_profile.display_name
        except AdminProfile.DoesNotExist:
            return None
import json
from .models import ChatRoom, Message, Poll, PollOption, PollVote, UserProfile
import asyncio

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.room_name}'
        self.user = self.scope["user"]
        
        if not self.user.is_authenticated:
            await self.close()
            return
        
        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()
        
        # Send recent messages to the newly connected user
        await self.send_recent_messages()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'chat_message':
                await self.handle_chat_message(data)
            elif message_type == 'poll_create':
                await self.handle_poll_create(data)
            elif message_type == 'poll_vote':
                await self.handle_poll_vote(data)
            elif message_type == 'pin_message':
                await self.handle_pin_message(data)
            elif message_type == 'search_messages':
                await self.handle_search_messages(data)
            
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'error': 'Invalid JSON'
            }))

    async def handle_chat_message(self, data):
        message_content = data['message']
        reply_to_id = data.get('reply_to_id')
        
        # Check if user is premium for sending messages
        user_profile = await self.get_user_profile(self.user)
        if not user_profile.is_premium:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Premium membership required to send messages'
            }))
            return
        
        # Filter abusive content (simple implementation)
        if await self.is_abusive_content(message_content):
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Your message contains inappropriate content and cannot be sent.'
            }))
            return
        
        # Save message to database
        message = await self.save_message(
            content=message_content,
            message_type='text',
            reply_to_id=reply_to_id
        )
        
        # Send message to room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': await self.format_message(message)
            }
        )
        
        # Handle AI response if it's an AI chat room
        room = await self.get_room()
        if room.is_ai_chat:
            await self.send_ai_response(message)

    async def handle_poll_create(self, data):
        user_profile = await self.get_user_profile(self.user)
        if not user_profile.is_premium:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Premium membership required to create polls'
            }))
            return
        
        question = data['question']
        options = data['options']
        allow_multiple = data.get('allow_multiple_answers', False)
        
        # Create poll message
        message = await self.save_message(
            content=question,
            message_type='poll'
        )
        
        # Create poll and options
        poll = await self.create_poll(message, question, allow_multiple, options)
        
        # Send poll to room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'poll_message',
                'poll': await self.format_poll(poll)
            }
        )

    async def handle_poll_vote(self, data):
        poll_option_id = data['option_id']
        poll_id = data['poll_id']
        
        result = await self.vote_on_poll(poll_option_id, poll_id)
        
        if result['success']:
            # Send updated poll to room group
            poll = await self.get_poll(poll_id)
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'poll_update',
                    'poll': await self.format_poll(poll)
                }
            )
        else:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': result['error']
            }))

    async def handle_pin_message(self, data):
        message_id = data['message_id']
        
        # Check if user is admin/staff
        if not self.user.is_staff:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Only administrators can pin messages'
            }))
            return
        
        message = await self.pin_message(message_id)
        if message:
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'message_pinned',
                    'message': await self.format_message(message)
                }
            )

    async def handle_search_messages(self, data):
        query = data['query']
        messages = await self.search_messages(query)
        
        await self.send(text_data=json.dumps({
            'type': 'search_results',
            'messages': [await self.format_message(msg) for msg in messages]
        }))

    async def send_ai_response(self, user_message):
        # Simulate AI processing delay
        await asyncio.sleep(1.5)
        
        ai_responses = [
            "Thank you for your message! I'm currently in development and will be fully operational in 45 days.",
            "I appreciate your input. Once I'm live, I'll be able to provide comprehensive assistance.",
            "That's an interesting point! I'm learning and will be more helpful soon.",
            "Thanks for sharing that with me. My full capabilities will be available in 45 days."
        ]
        
        import random
        ai_response = random.choice(ai_responses)
        
        # Create AI user if doesn't exist
        ai_user = await self.get_or_create_ai_user()
        
        # Save AI message
        ai_message = await self.save_ai_message(ai_response, ai_user)
        
        # Send AI response to room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': await self.format_message(ai_message)
            }
        )

    # WebSocket message handlers
    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': event['message']
        }))

    async def poll_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'poll_message',
            'poll': event['poll']
        }))

    async def poll_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'poll_update',
            'poll': event['poll']
        }))

    async def message_pinned(self, event):
        await self.send(text_data=json.dumps({
            'type': 'message_pinned',
            'message': event['message']
        }))

    # Database operations
    @database_sync_to_async
    def get_room(self):
        room, created = ChatRoom.objects.get_or_create(
            name=self.room_name,
            defaults={'is_ai_chat': 'ai' in self.room_name}
        )
        return room

    @database_sync_to_async
    def get_user_profile(self, user):
        profile, created = UserProfile.objects.get_or_create(
            user=user,
            defaults={'is_premium': False}
        )
        return profile

    @database_sync_to_async
    def save_message(self, content, message_type='text', reply_to_id=None):
        room = ChatRoom.objects.get(name=self.room_name)
        reply_to = None
        if reply_to_id:
            try:
                reply_to = Message.objects.get(id=reply_to_id)
            except Message.DoesNotExist:
                pass
        
        message = Message.objects.create(
            room=room,
            sender=self.user,
            content=content,
            message_type=message_type,
            reply_to=reply_to
        )
        return message

    @database_sync_to_async
    def save_ai_message(self, content, ai_user):
        room = ChatRoom.objects.get(name=self.room_name)
        message = Message.objects.create(
            room=room,
            sender=ai_user,
            content=content,
            message_type='text'
        )
        return message

    @database_sync_to_async
    def create_poll(self, message, question, allow_multiple, options):
        poll = Poll.objects.create(
            message=message,
            question=question,
            allow_multiple_answers=allow_multiple
        )
        
        for option_text in options:
            PollOption.objects.create(
                poll=poll,
                text=option_text['text']
            )
        
        return poll

    @database_sync_to_async
    def vote_on_poll(self, option_id, poll_id):
        try:
            option = PollOption.objects.get(id=option_id, poll_id=poll_id)
            poll = option.poll
            
            # Check if user already voted on this poll
            existing_votes = PollVote.objects.filter(
                poll_option__poll=poll,
                user=self.user
            )
            
            if not poll.allow_multiple_answers and existing_votes.exists():
                # Remove existing vote and add new one
                existing_votes.delete()
                # Update vote counts
                for old_option in poll.options.all():
                    old_option.votes = old_option.pollvote_set.count()
                    old_option.save()
            
            # Check if user already voted for this specific option
            vote, created = PollVote.objects.get_or_create(
                poll_option=option,
                user=self.user
            )
            
            if not created:
                # User is removing their vote
                vote.delete()
            
            # Update vote count
            option.votes = option.pollvote_set.count()
            option.save()
            
            return {'success': True}
            
        except PollOption.DoesNotExist:
            return {'success': False, 'error': 'Poll option not found'}

    @database_sync_to_async
    def pin_message(self, message_id):
        try:
            message = Message.objects.get(id=message_id)
            message.is_pinned = True
            message.pinned_by = self.user
            message.save()
            return message
        except Message.DoesNotExist:
            return None

    @database_sync_to_async
    def search_messages(self, query):
        room = ChatRoom.objects.get(name=self.room_name)
        messages = Message.objects.filter(
            room=room,
            content__icontains=query
        ).order_by('-timestamp')[:20]
        return list(messages)

    @database_sync_to_async
    def get_recent_messages(self):
        room = ChatRoom.objects.get(name=self.room_name)
        messages = Message.objects.filter(room=room).order_by('-timestamp')[:50]
        return list(reversed(messages))

    @database_sync_to_async
    def get_poll(self, poll_id):
        return Poll.objects.get(id=poll_id)

    @database_sync_to_async
    def get_or_create_ai_user(self):
        ai_user, created = User.objects.get_or_create(
            username='AI_Assistant',
            defaults={
                'first_name': 'AI',
                'last_name': 'Assistant',
                'email': 'ai@assistant.com'
            }
        )
        return ai_user

    async def send_recent_messages(self):
        messages = await self.get_recent_messages()
        for message in messages:
            if message.message_type == 'poll':
                poll = await database_sync_to_async(
                    lambda: getattr(message, 'poll', None)
                )()
                if poll:
                    await self.send(text_data=json.dumps({
                        'type': 'poll_message',
                        'poll': await self.format_poll(poll)
                    }))
            else:
                await self.send(text_data=json.dumps({
                    'type': 'chat_message',
                    'message': await self.format_message(message),
                    'is_history': True
                }))

    @database_sync_to_async
    def format_message(self, message):
        return {
            'id': message.id,
            'sender': message.sender.get_full_name() or message.sender.username,
            'content': message.content,
            'timestamp': message.timestamp.strftime('%I:%M %p'),
            'message_type': message.message_type,
            'is_user': message.sender == self.user,
            'is_pinned': message.is_pinned,
            'reply_to': {
                'id': message.reply_to.id,
                'sender': message.reply_to.sender.get_full_name() or message.reply_to.sender.username,
                'content': message.reply_to.content[:50] + ('...' if len(message.reply_to.content) > 50 else '')
            } if message.reply_to else None
        }

    @database_sync_to_async
    def format_poll(self, poll):
        options = []
        for option in poll.options.all():
            user_votes = list(option.pollvote_set.values_list('user__username', flat=True))
            options.append({
                'id': option.id,
                'text': option.text,
                'votes': option.votes,
                'voters': user_votes,
                'user_voted': self.user.username in user_votes
            })
        
        total_votes = sum(opt['votes'] for opt in options)
        
        return {
            'id': poll.id,
            'message_id': poll.message.id,
            'question': poll.question,
            'options': options,
            'allow_multiple_answers': poll.allow_multiple_answers,
            'total_votes': total_votes,
            'created_by': poll.message.sender.get_full_name() or poll.message.sender.username,
            'timestamp': poll.message.timestamp.strftime('%I:%M %p')
        }

    @database_sync_to_async
    def is_abusive_content(self, content):
        # Simple implementation - you can integrate with AI moderation services
        abusive_words = ['spam', 'abuse', 'hate']  # Add more words
        content_lower = content.lower()
        return any(word in content_lower for word in abusive_words)