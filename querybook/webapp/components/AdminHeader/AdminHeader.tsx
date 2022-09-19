import React from 'react';
import { UserMenuHeader } from 'components/UserMenu/UserMenuHeader';
import history from 'lib/router-history';

export const AdminHeader: React.FunctionComponent = () => {

    return <div className="global-app-header">
        <div
            style={{
                display: 'flex',
                alignItems: 'center',
                cursor: 'pointer',
            }}
        >
            <img
                src={'/querybook/images/dataOS-querybook-logo.svg'}
                width="175"
                className="dataos-app-logo"
                title="Home"
                alt="Home"
                onClick={() => history.push('/')}
            />
        </div>
        <div style={{ marginLeft: 'auto' }}>
            <UserMenuHeader />
        </div>
    </div>
};
