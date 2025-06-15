import json
from datetime import timezone

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from .models import ChatRoom, Message, Poll, PollOption, PollVote
import asyncio
import random


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f'chat_{self.room_name}'
        self.user = self.scope["user"]

        print(f"=== WebSocket Connection Debug ===")
        print(f"Room name: {self.room_name}")
        print(f"User: {self.user}")
        print(f"User type: {type(self.user)}")
        print(f"Is authenticated: {getattr(self.user, 'is_authenticated', False)}")
        print(f"Headers: {dict(self.scope.get('headers', []))}")
        print(f"Query string: {self.scope.get('query_string', b'').decode()}")

        # Check if user is authenticated

        if self.scope["user"].is_authenticated:
            try:
                # Add to group
                await self.channel_layer.group_add(
                    self.room_group_name,
                    self.channel_name
                )
                print(f"✅ Added to group: {self.room_group_name}")

                # Accept connection
                await self.accept()
                print(f"✅ WebSocket connection accepted for user: {self.user.username}")

                # Send recent messages
                await self.send_recent_messages()
                print(f"✅ Recent messages sent")

            except Exception as e:
                print(f"❌ Error during connection: {e}")
                await self.close(code=4002)  # Custom close code for server error
        else:
            print("❌ User not authenticated, closing connection")
            await self.close(code=4001)  # Custom close code for authentication failure
            return

    async def disconnect(self, close_code):
        print(f"=== WebSocket Disconnection ===")
        print(f"Close code: {close_code}")
        print(f"User: {getattr(self, 'user', 'Unknown')}")

        if hasattr(self, 'room_group_name'):
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
            print(f"✅ Removed from group: {self.room_group_name}")

    async def send_connection_confirmation(self):
        """Send a confirmation message when connection is established"""
        await self.send(text_data=json.dumps({
            'type': 'connection_confirmed',
            'message': 'Connected successfully',
            'user': self.user.username,
            'timestamp': timezone.now().isoformat()
        }))

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            print(f"Received message type: {message_type}")
            
            # Handle ping/pong for connection keep-alive
            if message_type == 'ping':
                await self.send(text_data=json.dumps({'type': 'pong'}))
                return
                
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
            else:
                print(f"Unknown message type: {message_type}")

        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            await self.send(text_data=json.dumps({'type': 'error', 'message': 'Invalid JSON'}))
        except Exception as e:
            print(f"Error in receive: {e}")
            await self.send(text_data=json.dumps({'type': 'error', 'message': 'Server error'}))

    async def handle_chat_message(self, data):
        content = data['message']
        reply_to_id = data.get('reply_to_id')

        print(f"Handling chat message: {content}")  # Debug log

        # Check if user is paid (comment out for testing)
        # profile = await self.get_user_profile(self.user)
        # if not profile.paid:
        #     return await self.send_message(type='error', message='Premium membership required to send messages')

        # Check for abusive content (simplified for debugging)
        if await self.is_abusive(content):
            return await self.send_message(type='error', message='Inappropriate content - not sent.')

        # Save message to database
        message = await self.save_message(content, 'text', reply_to_id)
        print(f"Message saved with id: {message.id}")

        # Send to all users in the group
        formatted_message = await self.format_message(message)
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': formatted_message
            }
        )

        # Handle AI response if needed
        room = await self.get_or_create_room()
        if room.is_ai_chat:
            await self.send_ai_response(message)

    async def handle_poll_create(self, data):
        print(f"Creating poll with data: {data}")  # Debug log
        
        # Comment out for testing
        # profile = await self.get_user_profile(self.user)
        # if not profile.paid:
        #     return await self.send_message(type='error', message='Premium membership required to create polls')

        try:
            message = await self.save_message(data['question'], 'poll')
            poll = await self.create_poll(message, data['question'], data.get('allow_multiple_answers', False),
                                        data['options'])
            poll_data = await self.format_poll(poll)
            print(f"Poll created successfully: {poll_data}")  # Debug log
            
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'poll_message',
                    'poll': poll_data
                }
            )
        except Exception as e:
            print(f"Error creating poll: {e}")
            await self.send_message(type='error', message=f'Failed to create poll: {str(e)}')

    async def handle_poll_vote(self, data):
        result = await self.vote_on_poll(data['option_id'], data['poll_id'])
        if result['success']:
            poll = await self.get_poll(data['poll_id'])
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'poll_update',
                    'poll': await self.format_poll(poll)
                }
            )
        else:
            await self.send_message(type='error', message=result['error'])

    async def handle_pin_message(self, data):
        print(f"Handling pin message: {data}")  # Debug log
        
        if not self.user.is_staff:
            print(f"User {self.user.username} is not staff, cannot pin message")
            return await self.send_message(type='error', message='Only admins can pin messages')

        message_id = data.get('message_id')
        if not message_id:
            return await self.send_message(type='error', message='Message ID required')
            
        message = await self.pin_message(message_id)
        if message:
            print(f"Message {message_id} pinned successfully")
            formatted_message = await self.format_message(message)
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'message_pinned',
                    'message': formatted_message
                }
            )
        else:
            print(f"Failed to pin message {message_id}")
            await self.send_message(type='error', message='Message not found')

    async def handle_search_messages(self, data):
        results = await self.search_messages(data['query'])
        formatted = [await self.format_message(m) for m in results]
        await self.send(text_data=json.dumps({
            'type': 'search_results',
            'messages': formatted
        }))

    async def send_ai_response(self, user_message):
        await asyncio.sleep(1.5)
        choices = [
            "AI coming soon — available in 45 days.",
            "Learning... full features soon!",
            "Thanks, I'll get smarter by 2025 end.",
            "AI assistant is under development, stay tuned!"
        ]
        ai_resp = random.choice(choices)
        ai_user = await self.get_or_create_ai_user()
        ai_message = await self.save_ai_message(ai_resp, ai_user)
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': await self.format_message(ai_message)
            }
        )

    # Group send handlers
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

    # Helper methods
    async def send_message(self, **kwargs):
        await self.send(text_data=json.dumps(kwargs))

    @database_sync_to_async
    def get_or_create_room(self):
        room, created = ChatRoom.objects.get_or_create(
            name=self.room_name,
            defaults={'is_ai_chat': 'ai' in self.room_name.lower()}
        )
        return room

    @database_sync_to_async
    def get_user_profile(self, user):
        return user

    @database_sync_to_async
    def save_message(self, content, message_type, reply_to_id=None):
        room = self.get_or_create_room_sync()
        reply = None
        
        if reply_to_id:
            try:
                reply = Message.objects.get(id=reply_to_id)
            except Message.DoesNotExist:
                print(f"Reply message with id {reply_to_id} not found")
                reply = None

        message = Message.objects.create(
            room=room,
            sender=self.user,
            content=content,
            message_type=message_type,
            reply_to=reply
        )
        return message

    def get_or_create_room_sync(self):
        room, created = ChatRoom.objects.get_or_create(
            name=self.room_name,
            defaults={'is_ai_chat': 'ai' in self.room_name.lower()}
        )
        return room

    @database_sync_to_async
    def save_ai_message(self, content, ai_user):
        room = self.get_or_create_room_sync()
        return Message.objects.create(
            room=room,
            sender=ai_user,
            content=content,
            message_type='text'
        )

    @database_sync_to_async
    def format_message(self, msg):
        # Get sender name
        sender_name = msg.sender.username
        if hasattr(msg.sender, 'get_full_name') and msg.sender.get_full_name():
            sender_name = msg.sender.get_full_name()
        elif hasattr(msg.sender, 'full_name') and msg.sender.full_name:
            sender_name = msg.sender.full_name

        # Handle reply_to safely
        reply_to_data = None
        if msg.reply_to:
            try:
                reply_sender = msg.reply_to.sender.get_full_name() if hasattr(msg.reply_to.sender, 'get_full_name') and msg.reply_to.sender.get_full_name() else msg.reply_to.sender.username
                reply_to_data = {
                    'id': msg.reply_to.id,
                    'sender': reply_sender,
                    'content': msg.reply_to.content[:50] + ('...' if len(msg.reply_to.content) > 50 else '')
                }
            except Exception as e:
                print(f"Error formatting reply_to: {e}")
                reply_to_data = None

        return {
            'id': msg.id,
            'sender': sender_name,
            'content': msg.content,
            'timestamp': msg.timestamp.isoformat(),
            'is_pinned': getattr(msg, 'is_pinned', False),
            'reply_to': reply_to_data
        }

    @database_sync_to_async
    def get_recent_messages(self):
        room = self.get_or_create_room_sync()
        return list(Message.objects.filter(room=room).select_related('sender', 'reply_to').order_by('-timestamp')[:50])

    @database_sync_to_async
    def is_abusive(self, content):
        forbidden = ['spam', 'hate', 'abuse']
        low = content.lower()
        return any(w in low for w in forbidden)

    @database_sync_to_async
    def get_or_create_ai_user(self):
        User = self.user._class_  # Get the user model class
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
        msgs = await self.get_recent_messages()
        print(f"Sending {len(msgs)} recent messages")  # Debug log

        # Send messages in chronological order (oldest first)
        for m in reversed(msgs):
            formatted_msg = await self.format_message(m)
            await self.send(text_data=json.dumps({
                'type': 'chat_message',
                'message': formatted_msg,
                'is_history': True
            }))

    # Additional helper methods for polls, etc.
    @database_sync_to_async
    def create_poll(self, message, question, allow_multiple, options):
        poll = Poll.objects.create(
            message=message,
            question=question,
            allow_multiple_answers=allow_multiple
        )
        for opt in options:
            PollOption.objects.create(poll=poll, text=opt['text'])
        return poll

    @database_sync_to_async
    def vote_on_poll(self, opt_id, poll_id):
        try:
            option = PollOption.objects.get(id=opt_id, poll_id=poll_id)
        except PollOption.DoesNotExist:
            return {'success': False, 'error': 'Option not found'}

        # Check existing votes for this user on this poll
        existing_votes = PollVote.objects.filter(
            poll_option__poll=option.poll, 
            user=self.user
        )
        
        if not option.poll.allow_multiple_answers and existing_votes.exists():
            # Remove existing vote if not allowing multiple answers
            existing_votes.delete()

        # Toggle vote for this specific option
        vote, created = PollVote.objects.get_or_create(
            poll_option=option, 
            user=self.user
        )
        
        if not created:
            # User already voted for this option, remove the vote
            vote.delete()

        return {'success': True}

    @database_sync_to_async
    def get_poll(self, poll_id):
        return Poll.objects.get(id=poll_id)

    @database_sync_to_async
    def format_poll(self, poll):
        from django.db import transaction
        with transaction.atomic():
            opts = []
            # Use the explicit model reference instead of reverse relation
            poll_options = PollOption.objects.filter(poll=poll)
            
            for o in poll_options:
                # Get votes for this option
                votes_for_option = PollVote.objects.filter(poll_option=o)
                vote_count = votes_for_option.count()
                voters = list(votes_for_option.values_list('user__username', flat=True))
                
                opts.append({
                    'id': o.id,
                    'text': o.text,
                    'votes': vote_count,
                    'voters': voters,
                    'user_voted': self.user.username in voters
                })
            
            sender_name = poll.message.sender.get_full_name() if hasattr(poll.message.sender, 'get_full_name') and poll.message.sender.get_full_name() else poll.message.sender.username
            
            return {
                'id': poll.id,
                'message_id': poll.message.id,
                'question': poll.question,
                'options': opts,
                'allow_multiple_answers': poll.allow_multiple_answers,
                'total_votes': sum(o['votes'] for o in opts),
                'created_by': sender_name
            }

    @database_sync_to_async
    def pin_message(self, message_id):
        try:
            msg = Message.objects.select_related('sender', 'reply_to').get(id=message_id)
            msg.is_pinned = True
            msg.save()
            print(f"Database: Message {message_id} pinned successfully")
            return msg
        except Message.DoesNotExist:
            print(f"Database: Message {message_id} not found")
            return None
        except Exception as e:
            print(f"Database error pinning message: {e}")
            return None

    @database_sync_to_async
    def search_messages(self, query):
        room = self.get_or_create_room_sync()
        return list(Message.objects.filter(
            room=room,
            content__icontains=query
        ).select_related('sender').order_by('-timestamp')[:20])