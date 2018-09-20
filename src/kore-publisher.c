#include "kore-publisher.h"

ht hash_table;

typedef struct myconnection {
	amqp_connection_state_t		*amqp_connection;
	pthread_mutex_t			mutex;	
}connection_t; 

int
ep_index(struct http_request *req)
{
	http_response(req, 200, "index-page",10 );
	return (KORE_RESULT_OK);
}

int
init (int state)
{
	if (worker->id > 0)
	{
		ht_init (&hash_table);
	}

	return KORE_RESULT_OK;
}

int
ep_publish (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *exchange;
	const char *topic;
	const char *message;

	amqp_basic_properties_t props;

	char id_apikey[258];

	amqp_socket_t 		*socket;
	connection_t 		*connection;

	node *c = NULL;

	amqp_rpc_reply_t 	login_reply;
	amqp_rpc_reply_t 	rpc_reply;

	dprintf("%d\n",http_request_header(req, "id", &id)); 
	dprintf("%d\n",http_request_header(req, "apikey", &apikey)); 
	dprintf("%d\n",http_request_header(req, "to", &exchange)); 
	dprintf("%d\n",http_request_header(req, "topic", &topic)); 
	dprintf("%d\n",http_request_header(req, "message", &message)); 

	if ( KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
	    KORE_RESULT_OK != http_request_header(req, "to", &exchange)
				||
	    KORE_RESULT_OK != http_request_header(req, "topic", &topic)
	)
	{
		bad_request();
	}

	if (http_request_header(req, "id", &id) != KORE_RESULT_OK)
	{
		if (http_request_header(req, "X-Consumer-Username", &id) != KORE_RESULT_OK)
		{
			bad_request();
		}
	}

	if (http_request_header(req, "message", &message) != KORE_RESULT_OK)
	{
		if (!(message = (char *)req->http_body->data))	
			bad_request();
	}

	/* TODO check with ldap */

	strlcpy(id_apikey,id,128);
	strlcat(id_apikey,":",1);
	strlcat(id_apikey,apikey,128);

	if ((c = ht_search(&hash_table,id_apikey)))
	{
		connection = c->value;
		/* TODO if connection->amqp_connection is closed, then:
			 goto reconnect */
	}
	else
	{
		connection = malloc(sizeof(connection_t));
		if (connection == NULL)
		{
			internal_error();
		}

		connection->amqp_connection = malloc(sizeof(amqp_connection_state_t));
		if (connection->amqp_connection == NULL)
		{
			free(connection);
			internal_error();
		}

		if (pthread_mutex_init(&connection->mutex,0) != 0)
		{
			free(connection->amqp_connection);
			free(connection);
			internal_error();
		}

reconnect:
		*(connection->amqp_connection) = amqp_new_connection();
		socket 	= amqp_tcp_socket_new(*(connection->amqp_connection));

		if (socket == NULL)
		{
			amqp_channel_close	(*(connection->amqp_connection), 1, AMQP_REPLY_SUCCESS);
			amqp_connection_close	(*(connection->amqp_connection), AMQP_REPLY_SUCCESS);
			amqp_destroy_connection	(*(connection->amqp_connection));

			free(connection->amqp_connection);
			free(connection);
			internal_error();
		}

		if (amqp_socket_open(socket, "broker", 5672))
		{
			amqp_channel_close	(*(connection->amqp_connection), 1, AMQP_REPLY_SUCCESS);
			amqp_connection_close	(*(connection->amqp_connection), AMQP_REPLY_SUCCESS);
			amqp_destroy_connection	(*(connection->amqp_connection));

			free(connection->amqp_connection);
			free(connection);
			internal_error();
		}

		login_reply = amqp_login(*(connection->amqp_connection), "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, id, apikey);
		if (login_reply.reply_type != AMQP_RESPONSE_NORMAL) {
			forbidden();
		}

		if (! amqp_channel_open(*(connection->amqp_connection), 1)) {
			forbidden();
		}

		rpc_reply = amqp_get_rpc_reply(*(connection->amqp_connection));
		if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL) {
			forbidden();
		}

		ht_insert (&hash_table, id_apikey, connection);
	}

	memset(&props, 0, sizeof props);
	props.user_id = amqp_cstring_bytes(id);

	pthread_mutex_lock(&connection->mutex);
	if (AMQP_STATUS_OK != amqp_basic_publish (	
				*(connection->amqp_connection),
				1,
				amqp_cstring_bytes(exchange),
               	 		amqp_cstring_bytes(topic),
				0,
				0,
				NULL,
               			amqp_cstring_bytes(message))
	)
	{
		pthread_mutex_unlock(&connection->mutex);
		forbidden();
	}
	pthread_mutex_unlock(&connection->mutex);

	ok202();
}
