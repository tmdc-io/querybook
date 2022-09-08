import clsx from 'clsx';
import * as React from 'react';

import { Icon } from 'ui/Icon/Icon';
import type { AllLucideIconNames } from 'ui/Icon/LucideIcons';
import { StyledText, UntitledText } from 'ui/StyledText/StyledText';

import { ILinkProps, Link } from './Link';

import './ListLink.scss';

interface IProps extends ILinkProps {
    className?: string;
    title?: string;
    noPlaceHolder?: boolean;
    icon?: AllLucideIconNames;
    isRow?: boolean;
}

export const ListLink: React.FunctionComponent<IProps> = React.memo(
    ({
        className,
        title,
        icon,
        isRow,
        noPlaceHolder = false,
        children,
        ...listProps
    }) => {
        const mergedClassName = clsx({
            ListLink: true,
            [className]: !!className,
            row: isRow,
        });
        return (
            <Link className={mergedClassName} {...listProps}>
                {title ? (
                    <StyledText className="ListLinkText" size="small">
                        {title}
                    </StyledText>
                ) : noPlaceHolder ? null : (
                    <UntitledText size="small" />
                )}
                {children}
                {icon && <span className="ml8" style={{lineHeight:0}}><Icon name={icon} size={12} /></span>}
            </Link>
        );
    }
);
